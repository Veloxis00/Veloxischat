"""
Vlxchat backend — Veloxis secure relay server.

Design goals:
  * The server NEVER sees plaintext. Clients derive an AES-256-GCM key
    client-side (PBKDF2 from a shared passphrase + room code) and encrypt
    every message before it ever reaches this process.
  * No database, no disk writes, no message logs. Everything lives in
    per-room in-memory sets that vanish the moment the room empties.
  * The server's job is narrow on purpose: authenticate a websocket into a
    room, relay opaque ciphertext blobs between the sockets in that room,
    and enforce a handful of abuse controls (rate limits, room size,
    payload size, room-count limits).
"""

import json
import time
import secrets
import logging
from collections import defaultdict, deque

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.middleware.base import BaseHTTPMiddleware

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
MAX_CLIENTS_PER_ROOM = 20
MAX_ROOMS = 500
MAX_MESSAGE_BYTES = 32 * 1024          # 32 KB ciphertext payload cap
RATE_WINDOW_SECONDS = 5
RATE_MAX_MESSAGES = 15                  # per window, per connection
IDLE_ROOM_SECONDS = 60 * 60             # rooms with no traffic get reaped

# We deliberately do NOT log message content anywhere. This logger only
# ever sees room codes (which are high-entropy and not sensitive on their
# own) and connection counts.
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("vlxchat")

app = FastAPI(title="Vlxchat Relay", docs_url=None, redoc_url=None)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self' wss: ws:; "
            "img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'"
        )
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)

# --------------------------------------------------------------------------
# In-memory room state (no persistence, ever)
# --------------------------------------------------------------------------
rooms: dict[str, set[WebSocket]] = defaultdict(set)
room_last_activity: dict[str, float] = {}
socket_names: dict[WebSocket, str] = {}
socket_room: dict[WebSocket, str] = {}
socket_msg_times: dict[WebSocket, deque] = defaultdict(deque)


def _touch(room: str) -> None:
    room_last_activity[room] = time.time()


def _reap_idle_rooms() -> None:
    now = time.time()
    dead = [
        r for r, ts in room_last_activity.items()
        if now - ts > IDLE_ROOM_SECONDS and not rooms.get(r)
    ]
    for r in dead:
        room_last_activity.pop(r, None)
        rooms.pop(r, None)


async def _broadcast(room: str, payload: str, exclude: WebSocket | None) -> None:
    dead = []
    for peer in rooms.get(room, set()):
        if peer is exclude:
            continue
        try:
            await peer.send_text(payload)
        except Exception:
            dead.append(peer)
    for d in dead:
        rooms[room].discard(d)


def _rate_limited(ws: WebSocket) -> bool:
    now = time.time()
    q = socket_msg_times[ws]
    q.append(now)
    while q and now - q[0] > RATE_WINDOW_SECONDS:
        q.popleft()
    return len(q) > RATE_MAX_MESSAGES


@app.websocket("/ws/{room_code}")
async def ws_endpoint(websocket: WebSocket, room_code: str):
    room_code = room_code.strip()[:64]
    if not room_code:
        await websocket.close(code=4000)
        return

    _reap_idle_rooms()

    if room_code not in rooms and len(rooms) >= MAX_ROOMS:
        await websocket.close(code=4008)  # too many rooms server-wide
        return

    if len(rooms[room_code]) >= MAX_CLIENTS_PER_ROOM:
        await websocket.close(code=4001)  # room full
        return

    await websocket.accept()
    rooms[room_code].add(websocket)
    socket_room[websocket] = room_code
    _touch(room_code)
    log.info("join room=%s size=%d", room_code, len(rooms[room_code]))

    # Tell the room how many peers are present (metadata only, no content)
    await _broadcast(
        room_code,
        json.dumps({"type": "presence", "count": len(rooms[room_code])}),
        exclude=None,
    )

    try:
        while True:
            raw = await websocket.receive_text()

            if len(raw.encode("utf-8")) > MAX_MESSAGE_BYTES:
                await websocket.send_text(
                    json.dumps({"type": "error", "reason": "message_too_large"})
                )
                continue

            if _rate_limited(websocket):
                await websocket.send_text(
                    json.dumps({"type": "error", "reason": "rate_limited"})
                )
                continue

            # We never parse or inspect the ciphertext. We only check that
            # it's well-formed JSON with an expected envelope shape, then
            # relay it verbatim.
            try:
                envelope = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if envelope.get("type") not in ("msg", "typing", "leave-notice"):
                continue

            socket_names[websocket] = str(envelope.get("name", "anon"))[:40]
            _touch(room_code)
            await _broadcast(room_code, raw, exclude=websocket)

    except WebSocketDisconnect:
        pass
    finally:
        rooms[room_code].discard(websocket)
        socket_room.pop(websocket, None)
        socket_names.pop(websocket, None)
        socket_msg_times.pop(websocket, None)
        if rooms.get(room_code):
            await _broadcast(
                room_code,
                json.dumps({"type": "presence", "count": len(rooms[room_code])}),
                exclude=None,
            )
        else:
            rooms.pop(room_code, None)
        log.info("leave room=%s", room_code)


@app.get("/health")
async def health():
    return {"status": "ok", "active_rooms": len(rooms)}


# --------------------------------------------------------------------------
# Static frontend (optional — only served if a static/ folder is present).
# A desktop-only deployment can skip this entirely: just don't include a
# static/ folder in the repo, and this server runs as a pure relay.
# --------------------------------------------------------------------------
import os

if os.path.isdir("static"):
    app.mount("/assets", StaticFiles(directory="static"), name="assets")

    @app.get("/")
    async def index():
        return FileResponse("static/index.html")
else:
    @app.get("/")
    async def index():
        return {"status": "vlxchat relay running", "web_ui": "not deployed"}

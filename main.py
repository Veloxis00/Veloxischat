"""
Vlxchat backend v2 — accounts, contacts, and an authenticated relay with
offline delivery.

What the server knows: usernames, password hashes, public keys (for
end-to-end key exchange), and the contact graph (who is friends with
whom). What the server does NOT know, ever: private keys, passphrases,
PINs, or plaintext message/file content. Every "envelope" it relays or
queues is exactly the opaque ciphertext blob the sender's client produced;
the server only reads the outer routing field ("to") to decide where it
goes.

Delivery model: if the recipient is connected right now, the envelope is
forwarded immediately over their WebSocket. If not, it's stored (still
ciphertext) in `pending_messages` until they next connect, then deleted.
"""

import os
import time
import json
import logging
from collections import defaultdict, deque

import jwt
from passlib.hash import bcrypt
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Header
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

import db

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
JWT_ALGO = "HS256"
JWT_TTL_SECONDS = 60 * 60 * 24 * 30  # 30 days

MAX_ENVELOPE_BYTES = 300 * 1024       # covers both chat text and file chunks
RATE_WINDOW_SECONDS = 5
RATE_MAX_MESSAGES = 30                 # count-based limit, applies uniformly
BYTE_RATE_WINDOW_SECONDS = 5
BYTE_RATE_MAX_BYTES = 8 * 1024 * 1024  # sustained-transfer byte cap, applies uniformly

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("vlxchat")

app = FastAPI(title="Vlxchat", docs_url=None, redoc_url=None)

_jwt_secret: str | None = None


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response


app.add_middleware(SecurityHeadersMiddleware)


@app.on_event("startup")
async def startup():
    global _jwt_secret
    await db.init_pool()
    _jwt_secret = await db.get_or_create_jwt_secret()
    log.info("startup complete, db pool ready")


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------

def make_token(user_id: int, username: str) -> str:
    payload = {"sub": user_id, "username": username, "iat": int(time.time()),
               "exp": int(time.time()) + JWT_TTL_SECONDS}
    return jwt.encode(payload, _jwt_secret, algorithm=JWT_ALGO)


def decode_token(token: str) -> dict:
    return jwt.decode(token, _jwt_secret, algorithms=[JWT_ALGO])


async def current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization[len("Bearer "):]
    try:
        payload = decode_token(token)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    return {"id": payload["sub"], "username": payload["username"]}


USERNAME_RE_MAX = 32


def valid_username(u: str) -> bool:
    return 3 <= len(u) <= USERNAME_RE_MAX and u.replace("_", "").replace("-", "").isalnum()


# --------------------------------------------------------------------------
# REST: auth
# --------------------------------------------------------------------------

class RegisterBody(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=256)
    public_key: str = Field(min_length=1, max_length=200)


class LoginBody(BaseModel):
    username: str
    password: str


@app.post("/auth/register")
async def register(body: RegisterBody):
    if not valid_username(body.username):
        raise HTTPException(400, "Érvénytelen felhasználónév (3-32 karakter, betű/szám/_/-).")
    existing = await db.get_user_by_username(body.username)
    if existing:
        raise HTTPException(409, "Ez a felhasználónév már foglalt.")
    pw_hash = bcrypt.hash(body.password)
    user_id = await db.create_user(body.username, pw_hash, body.public_key)
    return {"token": make_token(user_id, body.username), "user_id": user_id, "username": body.username}


@app.post("/auth/login")
async def login(body: LoginBody):
    row = await db.get_user_by_username(body.username)
    if not row or not bcrypt.verify(body.password, row["password_hash"]):
        raise HTTPException(401, "Hibás felhasználónév vagy jelszó.")
    return {"token": make_token(row["id"], row["username"]), "user_id": row["id"], "username": row["username"]}


# --------------------------------------------------------------------------
# REST: contacts
# --------------------------------------------------------------------------

class ContactRequestBody(BaseModel):
    username: str


class ContactRespondBody(BaseModel):
    request_id: int
    accept: bool


@app.get("/users/lookup")
async def lookup_user(username: str, me=Depends(current_user)):
    row = await db.get_user_by_username(username)
    if not row:
        raise HTTPException(404, "Nincs ilyen felhasználó.")
    return {"id": row["id"], "username": row["username"], "public_key": row["public_key"]}


@app.post("/contacts/request")
async def request_contact(body: ContactRequestBody, me=Depends(current_user)):
    if body.username == me["username"]:
        raise HTTPException(400, "Saját magadat nem adhatod hozzá.")
    target = await db.get_user_by_username(body.username)
    if not target:
        raise HTTPException(404, "Nincs ilyen felhasználó.")
    status = await db.create_or_accept_request(int(me["id"]), target["id"])
    return {"status": status}


@app.post("/contacts/respond")
async def respond_contact(body: ContactRespondBody, me=Depends(current_user)):
    ok = await db.respond_to_request(body.request_id, int(me["id"]), body.accept)
    if not ok:
        raise HTTPException(404, "Nincs ilyen függő kérés.")
    return {"ok": True}


@app.get("/contacts")
async def get_contacts(me=Depends(current_user)):
    accepted, incoming, outgoing = await db.list_contacts(int(me["id"]))
    return {
        "contacts": [dict(r) for r in accepted],
        "incoming_requests": [dict(r) for r in incoming],
        "outgoing_requests": [dict(r) for r in outgoing],
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


# --------------------------------------------------------------------------
# WebSocket relay (authenticated)
# --------------------------------------------------------------------------

online: dict[int, WebSocket] = {}
msg_times: dict[int, deque] = defaultdict(deque)
byte_times: dict[int, deque] = defaultdict(lambda: deque())  # (timestamp, size)


def _rate_limited(user_id: int) -> bool:
    now = time.time()
    q = msg_times[user_id]
    q.append(now)
    while q and now - q[0] > RATE_WINDOW_SECONDS:
        q.popleft()
    return len(q) > RATE_MAX_MESSAGES


def _byte_rate_limited(user_id: int, size: int) -> bool:
    now = time.time()
    q = byte_times[user_id]
    q.append((now, size))
    while q and now - q[0][0] > BYTE_RATE_WINDOW_SECONDS:
        q.popleft()
    total = sum(s for _, s in q)
    return total > BYTE_RATE_MAX_BYTES


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token", "")
    try:
        payload = decode_token(token)
    except jwt.PyJWTError:
        await websocket.close(code=4001)
        return

    user_id = int(payload["sub"])
    username = payload["username"]

    await websocket.accept()

    # Single active connection per account for this MVP: a new login takes
    # over from an older one.
    old = online.get(user_id)
    online[user_id] = websocket
    if old is not None and old is not websocket:
        try:
            await old.close(code=4009)
        except Exception:
            pass

    log.info("connect user=%s", username)

    # Flush anything that arrived while this user was offline.
    queued = await db.pop_pending(user_id)
    for from_user_id, envelope in queued:
        sender = await db.get_user_by_id(from_user_id)
        await websocket.send_text(json.dumps({
            "type": "deliver",
            "from": sender["username"] if sender else "unknown",
            "envelope": envelope,
        }))

    try:
        while True:
            raw = await websocket.receive_text()
            size = len(raw.encode("utf-8"))

            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            envelope = msg.get("envelope")
            to_username = msg.get("to")

            if size > MAX_ENVELOPE_BYTES:
                await websocket.send_text(json.dumps({"type": "error", "reason": "too_large"}))
                continue

            if _rate_limited(user_id) or _byte_rate_limited(user_id, size):
                await websocket.send_text(json.dumps({"type": "error", "reason": "rate_limited"}))
                continue

            if not to_username or envelope is None:
                continue

            target = await db.get_user_by_username(to_username)
            if not target:
                await websocket.send_text(json.dumps({"type": "error", "reason": "unknown_recipient"}))
                continue

            if not await db.are_contacts(user_id, target["id"]):
                await websocket.send_text(json.dumps({"type": "error", "reason": "not_a_contact"}))
                continue

            target_ws = online.get(target["id"])
            outgoing = json.dumps({"type": "deliver", "from": username, "envelope": envelope})

            if target_ws is not None:
                try:
                    await target_ws.send_text(outgoing)
                    continue
                except Exception:
                    online.pop(target["id"], None)

            ok = await db.queue_pending(user_id, target["id"], envelope)
            if not ok:
                await websocket.send_text(json.dumps({"type": "error", "reason": "recipient_queue_full"}))

    except WebSocketDisconnect:
        pass
    finally:
        if online.get(user_id) is websocket:
            online.pop(user_id, None)
        msg_times.pop(user_id, None)
        byte_times.pop(user_id, None)
        log.info("disconnect user=%s", username)

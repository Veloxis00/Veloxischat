"""
Vlxchat database layer — PostgreSQL via asyncpg.

Stores only what's needed to make accounts + contacts + offline delivery
work: usernames, password hashes, public keys, the contact graph, and a
*temporary* queue of end-to-end-encrypted envelopes for offline recipients.

The server never stores plaintext messages, private keys, passphrases, or
PINs. `pending_messages.envelope` is exactly the opaque ciphertext blob the
sender's client produced — the server can't read it, and deletes each row
the moment it's been handed to the recipient.
"""

import os
import json
import secrets

import asyncpg

_pool: asyncpg.Pool | None = None


def _normalize_dsn(url: str) -> str:
    # Railway (and Heroku-style) DATABASE_URLs often use the legacy
    # "postgres://" scheme, which asyncpg doesn't accept.
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return url


async def init_pool() -> asyncpg.Pool:
    global _pool
    dsn = _normalize_dsn(os.environ["DATABASE_URL"])
    _pool = await asyncpg.create_pool(dsn, min_size=1, max_size=10)
    await _init_schema(_pool)
    return _pool


def pool() -> asyncpg.Pool:
    assert _pool is not None, "DB pool not initialized"
    return _pool


async def _init_schema(p: asyncpg.Pool) -> None:
    async with p.acquire() as con:
        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS config (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                public_key    TEXT NOT NULL,
                created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS contacts (
                id            SERIAL PRIMARY KEY,
                requester_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                addressee_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                status        TEXT NOT NULL DEFAULT 'pending',
                created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
                UNIQUE(requester_id, addressee_id)
            );

            CREATE TABLE IF NOT EXISTS pending_messages (
                id          BIGSERIAL PRIMARY KEY,
                from_user   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                to_user     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                envelope    JSONB NOT NULL,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            CREATE INDEX IF NOT EXISTS idx_pending_to_user
                ON pending_messages(to_user);
            """
        )


async def get_or_create_jwt_secret() -> str:
    p = pool()
    async with p.acquire() as con:
        row = await con.fetchrow("SELECT value FROM config WHERE key = 'jwt_secret'")
        if row:
            return row["value"]
        secret = secrets.token_hex(32)
        await con.execute(
            "INSERT INTO config (key, value) VALUES ('jwt_secret', $1) "
            "ON CONFLICT (key) DO NOTHING",
            secret,
        )
        row = await con.fetchrow("SELECT value FROM config WHERE key = 'jwt_secret'")
        return row["value"]


# ------------------------------------------------------------------ users --

async def create_user(username: str, password_hash: str, public_key: str) -> int:
    p = pool()
    row = await p.fetchrow(
        "INSERT INTO users (username, password_hash, public_key) "
        "VALUES ($1, $2, $3) RETURNING id",
        username, password_hash, public_key,
    )
    return row["id"]


async def get_user_by_username(username: str):
    return await pool().fetchrow(
        "SELECT id, username, password_hash, public_key FROM users WHERE username = $1",
        username,
    )


async def get_user_by_id(user_id: int):
    return await pool().fetchrow(
        "SELECT id, username, public_key FROM users WHERE id = $1", user_id
    )


# -------------------------------------------------------------- contacts --

async def create_or_accept_request(requester_id: int, addressee_id: int) -> str:
    """Send a contact request. If the addressee already has a pending
    request TO the requester, auto-accept both directions. Returns the
    resulting status: 'pending' or 'accepted'."""
    p = pool()
    async with p.acquire() as con:
        async with con.transaction():
            reverse = await con.fetchrow(
                "SELECT id FROM contacts WHERE requester_id=$1 AND addressee_id=$2 AND status='pending'",
                addressee_id, requester_id,
            )
            if reverse:
                await con.execute(
                    "UPDATE contacts SET status='accepted' WHERE id=$1", reverse["id"]
                )
                await con.execute(
                    "INSERT INTO contacts (requester_id, addressee_id, status) "
                    "VALUES ($1, $2, 'accepted') "
                    "ON CONFLICT (requester_id, addressee_id) DO UPDATE SET status='accepted'",
                    requester_id, addressee_id,
                )
                return "accepted"

            await con.execute(
                "INSERT INTO contacts (requester_id, addressee_id, status) "
                "VALUES ($1, $2, 'pending') "
                "ON CONFLICT (requester_id, addressee_id) DO NOTHING",
                requester_id, addressee_id,
            )
            return "pending"


async def respond_to_request(request_id: int, addressee_id: int, accept: bool) -> bool:
    p = pool()
    row = await p.fetchrow(
        "SELECT id FROM contacts WHERE id=$1 AND addressee_id=$2 AND status='pending'",
        request_id, addressee_id,
    )
    if not row:
        return False
    new_status = "accepted" if accept else "rejected"
    await p.execute("UPDATE contacts SET status=$1 WHERE id=$2", new_status, request_id)
    return True


async def list_contacts(user_id: int):
    p = pool()
    accepted = await p.fetch(
        """
        SELECT u.id, u.username, u.public_key
        FROM contacts c
        JOIN users u ON u.id = CASE WHEN c.requester_id = $1 THEN c.addressee_id ELSE c.requester_id END
        WHERE (c.requester_id = $1 OR c.addressee_id = $1) AND c.status = 'accepted'
        """,
        user_id,
    )
    incoming = await p.fetch(
        """
        SELECT c.id AS request_id, u.id AS user_id, u.username
        FROM contacts c JOIN users u ON u.id = c.requester_id
        WHERE c.addressee_id = $1 AND c.status = 'pending'
        """,
        user_id,
    )
    outgoing = await p.fetch(
        """
        SELECT c.id AS request_id, u.id AS user_id, u.username
        FROM contacts c JOIN users u ON u.id = c.addressee_id
        WHERE c.requester_id = $1 AND c.status = 'pending'
        """,
        user_id,
    )
    return accepted, incoming, outgoing


async def are_contacts(user_a: int, user_b: int) -> bool:
    row = await pool().fetchrow(
        "SELECT 1 FROM contacts WHERE status='accepted' AND "
        "((requester_id=$1 AND addressee_id=$2) OR (requester_id=$2 AND addressee_id=$1))",
        user_a, user_b,
    )
    return row is not None


# ------------------------------------------------------------------ queue --

MAX_PENDING_PER_USER = 500


async def queue_pending(from_user: int, to_user: int, envelope: dict) -> bool:
    p = pool()
    count = await p.fetchval(
        "SELECT count(*) FROM pending_messages WHERE to_user = $1", to_user
    )
    if count >= MAX_PENDING_PER_USER:
        return False
    await p.execute(
        "INSERT INTO pending_messages (from_user, to_user, envelope) VALUES ($1, $2, $3)",
        from_user, to_user, json.dumps(envelope),
    )
    return True


async def pop_pending(to_user: int):
    """Fetch and delete all queued envelopes for a user (called once they
    connect). Returns a list of (from_user_id, envelope_dict)."""
    p = pool()
    async with p.acquire() as con:
        async with con.transaction():
            rows = await con.fetch(
                "SELECT id, from_user, envelope FROM pending_messages "
                "WHERE to_user = $1 ORDER BY id",
                to_user,
            )
            if rows:
                ids = [r["id"] for r in rows]
                await con.execute(
                    "DELETE FROM pending_messages WHERE id = ANY($1::bigint[])", ids
                )
            return [(r["from_user"], json.loads(r["envelope"])) for r in rows]

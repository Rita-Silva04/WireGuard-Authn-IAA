"""
Central SQLite database for the VPN authentication stack.
Tables:
  users            - core user accounts (+ failed_attempts, locked_until for §1.10)
  passwords        - scrypt verifier + salt for challenge-response (§1.6)
  totp_secrets     - TOTP seeds, AES-256-GCM encrypted at rest (§4.6)
  fido2_credentials- WebAuthn/FIDO2 credentials
  oauth_codes      - short-lived authorization codes
  oauth_tokens     - issued access tokens (stored as SHA-256 hash, single-use, §1.8)
  rba_events       - authentication events for RBA
  rba_ip_history   - per-user IP history
  wg_peers         - issued WireGuard peer configs (+ expires_at for §4.1/4.2)
  mfa_sessions     - per-login MFA state (+ password_nonce, nonce_consumed for §1.6)
"""

import base64
import sqlite3
import os
import hashlib
import ipaddress
import threading
import time
from contextlib import contextmanager

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_PATH = os.environ.get("DB_PATH", "/data/vpnauth.db")

# Bump this whenever the schema changes so old databases are recreated.
# v1 — Phase 1: scrypt password verifier, hashed/single-use tokens, lockout
#               columns on users, password nonce on mfa_sessions.
# v2 — Phase 4: expires_at on wg_peers (§4.1); totp_secrets.secret renamed to
#               secret_enc (AES-256-GCM ciphertext, §4.6).
# v3 — Store the username requested by UserAuthn as an OAuth login hint.
SCHEMA_VERSION = 3

_local = threading.local()


class NoFreeIPError(Exception):
    """Raised when no IP is free in the configured subnet."""


def get_conn():
    if not hasattr(_local, "conn") or _local.conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return _local.conn


@contextmanager
def db():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def _current_schema_version(conn) -> int:
    row = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name='schema_version'"
    ).fetchone()
    if not row:
        # Detect Phase 0 schema (no schema_version table). If the users table
        # exists, treat the DB as version 0 so init_db() can wipe and recreate.
        users_exists = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='users'"
        ).fetchone() is not None
        return 0 if users_exists else -1
    row = conn.execute("SELECT version FROM schema_version").fetchone()
    return row["version"] if row else 0


def _drop_all_tables(conn):
    """Drop every user-defined table — used when migrating between schemas."""
    # Foreign-key enforcement is on by default; turn it off for the duration
    # of the wipe so DROP TABLE order doesn't matter.
    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        tables = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        for t in tables:
            conn.execute(f"DROP TABLE IF EXISTS {t['name']}")
    finally:
        conn.execute("PRAGMA foreign_keys=ON")


def init_db():
    # Schema-mismatch migration: if the persisted DB was created by an older
    # codebase, the simplest correct action is to remove the file and let it
    # be recreated from scratch (§Phase 1 changed several column shapes —
    # there is no in-place migration). Foreign-key constraints make a
    # table-by-table wipe inside a transaction fragile; deleting the file
    # avoids that entire class of problems.
    if os.path.exists(DB_PATH):
        try:
            probe = sqlite3.connect(DB_PATH)
            probe.row_factory = sqlite3.Row
            current = _current_schema_version(probe)
            probe.close()
        except sqlite3.DatabaseError:
            current = -1
        if current >= 0 and current != SCHEMA_VERSION:
            print(f"[DB] Schema v{current} found, expected v{SCHEMA_VERSION} "
                  f"— wiping {DB_PATH} to rebuild from scratch.")
            # Drop the thread-local connection (if any) so the next get_conn()
            # opens a fresh one against the new file.
            if hasattr(_local, "conn") and _local.conn is not None:
                _local.conn.close()
                _local.conn = None
            os.unlink(DB_PATH)
            for suffix in ("-wal", "-shm"):
                p = DB_PATH + suffix
                if os.path.exists(p):
                    os.unlink(p)

    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    UNIQUE NOT NULL,
            display_name    TEXT,
            active          INTEGER DEFAULT 1,
            failed_attempts INTEGER DEFAULT 0,
            locked_until    INTEGER DEFAULT 0,
            last_failure_at INTEGER DEFAULT 0,
            created_at      TEXT    DEFAULT (datetime('now')),
            updated_at      TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS passwords (
            user_id     INTEGER PRIMARY KEY REFERENCES users(id),
            salt        BLOB NOT NULL,
            verifier    BLOB NOT NULL,
            updated_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS totp_secrets (
            user_id     INTEGER PRIMARY KEY REFERENCES users(id),
            secret_enc  BLOB    NOT NULL,
            confirmed   INTEGER DEFAULT 0,
            updated_at  TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS fido2_credentials (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            cred_id     TEXT NOT NULL UNIQUE,
            public_key  TEXT NOT NULL,
            sign_count  INTEGER DEFAULT 0,
            transports  TEXT DEFAULT '[]',
            name        TEXT DEFAULT 'YubiKey',
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id       TEXT PRIMARY KEY,
            client_secret   TEXT NOT NULL,
            name            TEXT NOT NULL,
            redirect_uris   TEXT DEFAULT '[]',
            scopes          TEXT DEFAULT 'vpn'
        );

        CREATE TABLE IF NOT EXISTS device_codes (
            device_code     TEXT PRIMARY KEY,
            user_code       TEXT UNIQUE NOT NULL,
            client_id       TEXT NOT NULL,
            scope           TEXT DEFAULT 'vpn',
            requested_username TEXT,
            user_id         INTEGER REFERENCES users(id),
            status          TEXT DEFAULT 'pending',
            expires_at      TEXT NOT NULL,
            created_at      TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS oauth_tokens (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash      TEXT UNIQUE NOT NULL,
            token_type      TEXT DEFAULT 'Bearer',
            user_id         INTEGER NOT NULL REFERENCES users(id),
            client_id       TEXT NOT NULL,
            scope           TEXT DEFAULT 'vpn',
            expires_at      TEXT NOT NULL,
            used_at         TEXT,
            created_at      TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS rba_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT NOT NULL,
            event_type      TEXT NOT NULL,
            success         INTEGER NOT NULL,
            ip_address      TEXT,
            asn             TEXT,
            user_agent      TEXT,
            risk_score      REAL DEFAULT 0.0,
            factors_used    TEXT DEFAULT '[]',
            created_at      TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS rba_ip_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL REFERENCES users(id),
            ip_address      TEXT NOT NULL,
            asn             TEXT,
            first_seen      TEXT DEFAULT (datetime('now')),
            last_seen       TEXT DEFAULT (datetime('now')),
            count           INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS wg_peers (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL REFERENCES users(id),
            interface       TEXT NOT NULL,
            client_pubkey   TEXT NOT NULL,
            client_ip       TEXT NOT NULL,
            psk             TEXT NOT NULL,
            active          INTEGER DEFAULT 1,
            created_at      TEXT DEFAULT (datetime('now')),
            expires_at      INTEGER NOT NULL,
            UNIQUE(user_id, interface)
        );

        CREATE TABLE IF NOT EXISTS mfa_sessions (
            session_id      TEXT PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id),
            device_code     TEXT NOT NULL,
            password_ok     INTEGER DEFAULT 0,
            totp_ok         INTEGER DEFAULT 0,
            fido2_ok        INTEGER DEFAULT 0,
            required_factors TEXT DEFAULT '[]',
            password_nonce  BLOB,
            nonce_consumed  INTEGER DEFAULT 0,
            expires_at      TEXT NOT NULL,
            created_at      TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY
        );
        """)
        # Record the schema version (idempotent).
        conn.execute("DELETE FROM schema_version")
        conn.execute("INSERT INTO schema_version (version) VALUES (?)",
                     (SCHEMA_VERSION,))
    print(f"[DB] Initialised at {DB_PATH} (schema v{SCHEMA_VERSION})")


# ── User helpers ───────────────────────────────────────────────────────────────

def get_user(username: str):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username=? AND active=1", (username,)
        ).fetchone()


def get_user_by_id(user_id: int):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE id=? AND active=1", (user_id,)
        ).fetchone()


def create_user(username: str, display_name: str = None):
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, display_name) VALUES (?,?)",
            (username, display_name or username)
        )
        return conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()


def list_users():
    with db() as conn:
        return conn.execute("SELECT * FROM users ORDER BY username").fetchall()


# ── Lockout helpers (§1.10) ────────────────────────────────────────────────────

LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW    = 300      # seconds — 5 minutes
LOCKOUT_DURATION  = 900      # seconds — 15 minutes


def is_user_locked(user_id: int) -> bool:
    """Return True if the user is currently locked out."""
    import time
    with db() as conn:
        row = conn.execute(
            "SELECT locked_until FROM users WHERE id=?", (user_id,)
        ).fetchone()
        if not row:
            return False
        return row["locked_until"] > int(time.time())


def lockout_seconds_remaining(user_id: int) -> int:
    import time
    with db() as conn:
        row = conn.execute(
            "SELECT locked_until FROM users WHERE id=?", (user_id,)
        ).fetchone()
        if not row:
            return 0
        return max(0, row["locked_until"] - int(time.time()))


def record_factor_failure(user_id: int):
    """Increment failure count; lock the account if threshold reached in window."""
    import time
    now = int(time.time())
    with db() as conn:
        row = conn.execute(
            "SELECT failed_attempts, last_failure_at FROM users WHERE id=?",
            (user_id,)
        ).fetchone()
        if not row:
            return
        # Reset counter if last failure is outside the window
        if now - row["last_failure_at"] > LOCKOUT_WINDOW:
            attempts = 1
        else:
            attempts = row["failed_attempts"] + 1

        if attempts >= LOCKOUT_THRESHOLD:
            conn.execute(
                "UPDATE users SET failed_attempts=0, "
                "last_failure_at=?, locked_until=? WHERE id=?",
                (now, now + LOCKOUT_DURATION, user_id),
            )
        else:
            conn.execute(
                "UPDATE users SET failed_attempts=?, last_failure_at=? "
                "WHERE id=?",
                (attempts, now, user_id),
            )


def reset_failed_attempts(user_id: int):
    """Clear failure counter after a fully successful authentication."""
    with db() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?",
            (user_id,),
        )


# ── Password helpers (challenge-response, §1.6) ────────────────────────────────

def set_password_verifier(user_id: int, salt: bytes, verifier: bytes):
    """Store (salt, verifier) for the scrypt-based challenge-response login."""
    with db() as conn:
        conn.execute("""
            INSERT INTO passwords (user_id, salt, verifier) VALUES (?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET salt=excluded.salt,
            verifier=excluded.verifier, updated_at=datetime('now')
        """, (user_id, salt, verifier))


def get_password_verifier(user_id: int):
    """Return (salt, verifier) tuple or None if the user has no password set."""
    with db() as conn:
        row = conn.execute(
            "SELECT salt, verifier FROM passwords WHERE user_id=?", (user_id,)
        ).fetchone()
        if not row:
            return None
        return (row["salt"], row["verifier"])


def has_password(user_id: int) -> bool:
    return get_password_verifier(user_id) is not None


# ── AES-256-GCM at-rest encryption for TOTP secrets (§4.6) ────────────────────

_aesgcm_cache: AESGCM | None = None
_aesgcm_lock = threading.Lock()


def _load_master_key() -> bytes:
    """
    Return the 32-byte master key from IAA_MASTER_KEY. The variable holds a
    base64-encoded 32-byte value (the natural shape that survives an
    env-var round trip). The fail-closed startup check in common/config.py
    guarantees this is non-empty and not a placeholder.
    """
    raw = os.environ.get("IAA_MASTER_KEY", "").strip()
    if not raw:
        raise RuntimeError(
            "IAA_MASTER_KEY not set — refusing to read/write encrypted secrets"
        )
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as e:
        raise RuntimeError(f"IAA_MASTER_KEY is not valid base64: {e}")
    if len(key) != 32:
        raise RuntimeError(
            f"IAA_MASTER_KEY must decode to 32 bytes (got {len(key)})"
        )
    return key


def _aesgcm() -> AESGCM:
    """Lazy + cached AESGCM instance keyed on IAA_MASTER_KEY."""
    global _aesgcm_cache
    if _aesgcm_cache is None:
        with _aesgcm_lock:
            if _aesgcm_cache is None:
                _aesgcm_cache = AESGCM(_load_master_key())
    return _aesgcm_cache


def _encrypt(plaintext: bytes) -> bytes:
    """
    Encrypt with AES-256-GCM. Returns ``nonce(12) || ciphertext || tag(16)`` so
    the result is a single self-describing BLOB we can store directly.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        plaintext = plaintext.encode()
    nonce = os.urandom(12)
    ct = _aesgcm().encrypt(nonce, bytes(plaintext), associated_data=None)
    return nonce + ct


def _decrypt(blob: bytes) -> bytes:
    """Inverse of :func:`_encrypt`. Raises if the tag fails to verify."""
    if not isinstance(blob, (bytes, bytearray)):
        blob = bytes(blob)
    if len(blob) < 12 + 16:
        raise ValueError("encrypted blob too short")
    nonce, ct = blob[:12], blob[12:]
    return _aesgcm().decrypt(nonce, ct, associated_data=None)


# ── TOTP helpers (secret encrypted at rest, §4.6) ─────────────────────────────

def set_totp_secret(user_id: int, secret: str, confirmed: bool = False):
    """Store the TOTP base32 seed as AES-256-GCM ciphertext."""
    blob = _encrypt(secret.encode())
    with db() as conn:
        conn.execute("""
            INSERT INTO totp_secrets (user_id, secret_enc, confirmed)
            VALUES (?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET secret_enc=excluded.secret_enc,
            confirmed=excluded.confirmed, updated_at=datetime('now')
        """, (user_id, blob, 1 if confirmed else 0))


def get_totp_secret(user_id: int):
    """
    Return ``{"secret": "<base32>", "confirmed": 0|1}`` or ``None``. The
    return shape stays a dict so callers that used ``row["secret"]`` and
    ``row["confirmed"]`` keep working unmodified.
    """
    with db() as conn:
        row = conn.execute(
            "SELECT secret_enc, confirmed FROM totp_secrets WHERE user_id=?",
            (user_id,)
        ).fetchone()
        if not row:
            return None
        plaintext = _decrypt(bytes(row["secret_enc"])).decode()
        return {"secret": plaintext, "confirmed": row["confirmed"]}


# ── FIDO2 helpers ──────────────────────────────────────────────────────────────

def add_fido2_credential(user_id: int, cred_id: str, public_key: str,
                          sign_count: int, transports: str, name: str = "YubiKey"):
    with db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO fido2_credentials
            (user_id, cred_id, public_key, sign_count, transports, name)
            VALUES (?,?,?,?,?,?)
        """, (user_id, cred_id, public_key, sign_count, transports, name))


def get_fido2_credentials(user_id: int):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM fido2_credentials WHERE user_id=?", (user_id,)
        ).fetchall()


def get_fido2_credential_by_id(cred_id: str):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM fido2_credentials WHERE cred_id=?", (cred_id,)
        ).fetchone()


def update_fido2_sign_count(cred_id: str, sign_count: int):
    with db() as conn:
        conn.execute(
            "UPDATE fido2_credentials SET sign_count=? WHERE cred_id=?",
            (sign_count, cred_id)
        )


# ── Device code (OAuth Device Grant) helpers ──────────────────────────────────

def create_device_code(device_code: str, user_code: str, client_id: str,
                       scope: str, expires_at: str,
                       requested_username: str | None = None):
    with db() as conn:
        conn.execute("""
            INSERT INTO device_codes
            (device_code, user_code, client_id, scope, requested_username, expires_at)
            VALUES (?,?,?,?,?,?)
        """, (device_code, user_code, client_id, scope, requested_username, expires_at))


def get_device_code(device_code: str):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM device_codes WHERE device_code=?", (device_code,)
        ).fetchone()


def get_device_code_by_user_code(user_code: str):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM device_codes WHERE user_code=?", (user_code,)
        ).fetchone()


def approve_device_code(device_code: str, user_id: int):
    with db() as conn:
        conn.execute("""
            UPDATE device_codes SET user_id=?, status='approved'
            WHERE device_code=?
        """, (user_id, device_code))


def deny_device_code(device_code: str):
    with db() as conn:
        conn.execute(
            "UPDATE device_codes SET status='denied' WHERE device_code=?",
            (device_code,)
        )


# ── OAuth token helpers (hashed, single-use, §1.8) ─────────────────────────────

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_access_token(access_token: str, user_id: int, client_id: str,
                         scope: str, expires_at: str):
    """Store SHA-256 hash of the token; the plaintext token is never persisted."""
    with db() as conn:
        conn.execute("""
            INSERT INTO oauth_tokens
            (token_hash, user_id, client_id, scope, expires_at)
            VALUES (?,?,?,?,?)
        """, (_hash_token(access_token), user_id, client_id, scope, expires_at))


def get_access_token(token: str):
    """Look up by hash of the presented token."""
    with db() as conn:
        return conn.execute(
            "SELECT * FROM oauth_tokens WHERE token_hash=?", (_hash_token(token),)
        ).fetchone()


def mark_token_used(token: str) -> bool:
    """
    Mark a token as used. Returns True if this call was the one that flipped
    used_at from NULL to now; False if it was already used (replay).
    """
    with db() as conn:
        cur = conn.execute(
            "UPDATE oauth_tokens SET used_at=datetime('now') "
            "WHERE token_hash=? AND used_at IS NULL",
            (_hash_token(token),)
        )
        return cur.rowcount == 1


# ── MFA session helpers ────────────────────────────────────────────────────────

def create_mfa_session(session_id: str, user_id: int, device_code: str,
                        required_factors: str, expires_at: str):
    with db() as conn:
        conn.execute("""
            INSERT INTO mfa_sessions
            (session_id, user_id, device_code, required_factors, expires_at)
            VALUES (?,?,?,?,?)
        """, (session_id, user_id, device_code, required_factors, expires_at))


def get_mfa_session(session_id: str):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM mfa_sessions WHERE session_id=?", (session_id,)
        ).fetchone()


def update_mfa_session(session_id: str, **kwargs):
    sets = ", ".join(f"{k}=?" for k in kwargs)
    vals = list(kwargs.values()) + [session_id]
    with db() as conn:
        conn.execute(
            f"UPDATE mfa_sessions SET {sets} WHERE session_id=?", vals
        )


def issue_password_nonce(session_id: str, nonce: bytes):
    """Set a fresh nonce for the password challenge and mark it unconsumed."""
    with db() as conn:
        conn.execute(
            "UPDATE mfa_sessions SET password_nonce=?, nonce_consumed=0 "
            "WHERE session_id=?",
            (nonce, session_id),
        )


def consume_password_nonce(session_id: str) -> bytes | None:
    """
    Atomically read the nonce and mark it consumed. Returns the nonce bytes
    if it was unconsumed (the caller may use it once); None if already consumed
    or missing (replay).
    """
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT password_nonce, nonce_consumed FROM mfa_sessions "
            "WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if not row or row["password_nonce"] is None or row["nonce_consumed"]:
            return None
        conn.execute(
            "UPDATE mfa_sessions SET nonce_consumed=1 WHERE session_id=?",
            (session_id,),
        )
        return bytes(row["password_nonce"])


# ── RBA helpers ────────────────────────────────────────────────────────────────

def log_rba_event(username: str, event_type: str, success: bool,
                   ip_address: str = None, asn: str = None,
                   risk_score: float = 0.0, factors_used: str = "[]",
                   user_agent: str = None):
    with db() as conn:
        conn.execute("""
            INSERT INTO rba_events
            (username, event_type, success, ip_address, asn,
             risk_score, factors_used, user_agent)
            VALUES (?,?,?,?,?,?,?,?)
        """, (username, event_type, 1 if success else 0,
              ip_address, asn, risk_score, factors_used, user_agent))


def get_recent_failures(username: str, minutes: int = 30):
    with db() as conn:
        return conn.execute("""
            SELECT COUNT(*) as cnt FROM rba_events
            WHERE username=? AND success=0
            AND created_at > datetime('now', ? || ' minutes')
        """, (username, f"-{minutes}")).fetchone()["cnt"]


def get_ip_history(user_id: int):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM rba_ip_history WHERE user_id=? ORDER BY last_seen DESC",
            (user_id,)
        ).fetchall()


def upsert_ip_history(user_id: int, ip_address: str, asn: str = None):
    with db() as conn:
        existing = conn.execute("""
            SELECT id FROM rba_ip_history
            WHERE user_id=? AND ip_address=?
        """, (user_id, ip_address)).fetchone()
        if existing:
            conn.execute("""
                UPDATE rba_ip_history
                SET last_seen=datetime('now'), count=count+1, asn=?
                WHERE user_id=? AND ip_address=?
            """, (asn, user_id, ip_address))
        else:
            conn.execute("""
                INSERT INTO rba_ip_history (user_id, ip_address, asn)
                VALUES (?,?,?)
            """, (user_id, ip_address, asn))


# ── WireGuard peer helpers ─────────────────────────────────────────────────────

DEFAULT_LEASE_TTL_SECONDS = 24 * 60 * 60   # 24 h


def upsert_wg_peer(user_id: int, interface: str, client_pubkey: str,
                    client_ip: str, psk: str,
                    lease_ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS):
    expires_at = int(time.time()) + int(lease_ttl_seconds)
    with db() as conn:
        conn.execute("""
            INSERT INTO wg_peers
            (user_id, interface, client_pubkey, client_ip, psk, expires_at)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(user_id, interface) DO UPDATE SET
            client_pubkey=excluded.client_pubkey,
            client_ip=excluded.client_ip,
            psk=excluded.psk,
            active=1,
            created_at=datetime('now'),
            expires_at=excluded.expires_at
        """, (user_id, interface, client_pubkey, client_ip, psk, expires_at))


def get_wg_peer(user_id: int, interface: str):
    with db() as conn:
        return conn.execute("""
            SELECT * FROM wg_peers WHERE user_id=? AND interface=? AND active=1
        """, (user_id, interface)).fetchone()


def get_all_wg_peers(interface: str):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM wg_peers WHERE interface=? AND active=1", (interface,)
        ).fetchall()


def get_expired_wg_peers(interface: str):
    """Return active peers whose ``expires_at`` is in the past (§4.2)."""
    now = int(time.time())
    with db() as conn:
        return conn.execute(
            "SELECT * FROM wg_peers "
            "WHERE interface=? AND active=1 AND expires_at < ?",
            (interface, now),
        ).fetchall()


def deactivate_wg_peer(peer_id: int):
    """Mark a peer inactive after the sweeper has removed it from wg0."""
    with db() as conn:
        conn.execute(
            "UPDATE wg_peers SET active=0 WHERE id=?", (peer_id,)
        )


def lease_next_ip(interface: str, subnet: str, user_id: int,
                  client_pubkey: str, psk: str,
                  lease_ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS) -> str:
    """
    Atomically find the next free IP in `subnet` and claim it for this user.

    The whole read-pick-write sequence runs inside a single BEGIN IMMEDIATE
    transaction so two concurrent requests cannot pick the same IP (§1.11).

    If the user already has an active lease on this interface, the existing
    row is updated in place (pubkey + psk refreshed) and the existing IP is
    returned — keeping pre-existing semantics from srvauthn.allocate_ip.

    Raises NoFreeIPError if the subnet is exhausted.
    """
    net = ipaddress.IPv4Network(subnet, strict=False)
    server_ip = str(list(net.hosts())[0])    # .1 is reserved for the server
    expires_at = int(time.time()) + int(lease_ttl_seconds)

    conn = get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")

        # Re-lease if this user already owns a row on this interface.
        existing = conn.execute(
            "SELECT client_ip FROM wg_peers "
            "WHERE user_id=? AND interface=? AND active=1",
            (user_id, interface),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE wg_peers SET client_pubkey=?, psk=?, "
                "created_at=datetime('now'), expires_at=? "
                "WHERE user_id=? AND interface=?",
                (client_pubkey, psk, expires_at, user_id, interface),
            )
            conn.commit()
            return existing["client_ip"]

        used = {row["client_ip"] for row in conn.execute(
            "SELECT client_ip FROM wg_peers WHERE interface=? AND active=1",
            (interface,),
        ).fetchall()}

        chosen = None
        for host in net.hosts():
            ip = str(host)
            if ip == server_ip:
                continue
            if ip not in used:
                chosen = ip
                break

        if chosen is None:
            conn.rollback()
            raise NoFreeIPError(f"No free IPs in {subnet}")

        conn.execute(
            "INSERT INTO wg_peers "
            "(user_id, interface, client_pubkey, client_ip, psk, expires_at) "
            "VALUES (?,?,?,?,?,?)",
            (user_id, interface, client_pubkey, chosen, psk, expires_at),
        )
        conn.commit()
        return chosen

    except Exception:
        conn.rollback()
        raise


# ── OAuth client helpers ───────────────────────────────────────────────────────

def get_oauth_client(client_id: str):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM oauth_clients WHERE client_id=?", (client_id,)
        ).fetchone()


def ensure_default_client():
    """Create the default SrvAuthn OAuth client if it doesn't exist."""
    client_secret = os.environ.get("OAUTH_CLIENT_SECRET", "srvauthn-secret")
    with db() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO oauth_clients
            (client_id, client_secret, name, scopes)
            VALUES ('srvauthn', ?, 'SrvAuthn Client', 'vpn')
        """, (client_secret,))


if __name__ == "__main__":
    init_db()
    ensure_default_client()
    print("Database ready.")

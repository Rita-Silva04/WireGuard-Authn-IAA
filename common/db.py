"""
Central SQLite database for the VPN authentication stack.
Tables:
  users            - core user accounts
  passwords        - hashed passwords
  totp_secrets     - TOTP seeds
  fido2_credentials- WebAuthn/FIDO2 credentials
  oauth_codes      - short-lived authorization codes
  oauth_tokens     - issued access/refresh tokens
  rba_events       - authentication events for RBA
  rba_ip_history   - per-user IP history
  wg_peers         - issued WireGuard peer configs
"""

import sqlite3
import os
import threading
from contextlib import contextmanager

DB_PATH = os.environ.get("DB_PATH", "/data/vpnauth.db")

_local = threading.local()


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


def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            display_name TEXT,
            active      INTEGER DEFAULT 1,
            created_at  TEXT    DEFAULT (datetime('now')),
            updated_at  TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS passwords (
            user_id     INTEGER PRIMARY KEY REFERENCES users(id),
            hash        TEXT NOT NULL,
            updated_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS totp_secrets (
            user_id     INTEGER PRIMARY KEY REFERENCES users(id),
            secret      TEXT NOT NULL,
            confirmed   INTEGER DEFAULT 0,
            updated_at  TEXT DEFAULT (datetime('now'))
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
            user_id         INTEGER REFERENCES users(id),
            status          TEXT DEFAULT 'pending',
            expires_at      TEXT NOT NULL,
            created_at      TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS oauth_tokens (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            access_token    TEXT UNIQUE NOT NULL,
            token_type      TEXT DEFAULT 'Bearer',
            user_id         INTEGER NOT NULL REFERENCES users(id),
            client_id       TEXT NOT NULL,
            scope           TEXT DEFAULT 'vpn',
            expires_at      TEXT NOT NULL,
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
            expires_at      TEXT NOT NULL,
            created_at      TEXT DEFAULT (datetime('now'))
        );
        """)
    print(f"[DB] Initialised at {DB_PATH}")


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


# ── Password helpers ───────────────────────────────────────────────────────────

def set_password(user_id: int, hashed: str):
    with db() as conn:
        conn.execute("""
            INSERT INTO passwords (user_id, hash) VALUES (?,?)
            ON CONFLICT(user_id) DO UPDATE SET hash=excluded.hash,
            updated_at=datetime('now')
        """, (user_id, hashed))


def get_password_hash(user_id: int):
    with db() as conn:
        row = conn.execute(
            "SELECT hash FROM passwords WHERE user_id=?", (user_id,)
        ).fetchone()
        return row["hash"] if row else None


# ── TOTP helpers ───────────────────────────────────────────────────────────────

def set_totp_secret(user_id: int, secret: str, confirmed: bool = False):
    with db() as conn:
        conn.execute("""
            INSERT INTO totp_secrets (user_id, secret, confirmed) VALUES (?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret,
            confirmed=excluded.confirmed, updated_at=datetime('now')
        """, (user_id, secret, 1 if confirmed else 0))


def get_totp_secret(user_id: int):
    with db() as conn:
        row = conn.execute(
            "SELECT secret, confirmed FROM totp_secrets WHERE user_id=?", (user_id,)
        ).fetchone()
        return row if row else None


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
                        scope: str, expires_at: str):
    with db() as conn:
        conn.execute("""
            INSERT INTO device_codes
            (device_code, user_code, client_id, scope, expires_at)
            VALUES (?,?,?,?,?)
        """, (device_code, user_code, client_id, scope, expires_at))


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


# ── OAuth token helpers ────────────────────────────────────────────────────────

def create_access_token(access_token: str, user_id: int, client_id: str,
                         scope: str, expires_at: str):
    with db() as conn:
        conn.execute("""
            INSERT INTO oauth_tokens
            (access_token, user_id, client_id, scope, expires_at)
            VALUES (?,?,?,?,?)
        """, (access_token, user_id, client_id, scope, expires_at))


def get_access_token(token: str):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM oauth_tokens WHERE access_token=?", (token,)
        ).fetchone()


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

def upsert_wg_peer(user_id: int, interface: str, client_pubkey: str,
                    client_ip: str, psk: str):
    with db() as conn:
        conn.execute("""
            INSERT INTO wg_peers (user_id, interface, client_pubkey, client_ip, psk)
            VALUES (?,?,?,?,?)
            ON CONFLICT(user_id, interface) DO UPDATE SET
            client_pubkey=excluded.client_pubkey,
            client_ip=excluded.client_ip,
            psk=excluded.psk,
            created_at=datetime('now')
        """, (user_id, interface, client_pubkey, client_ip, psk))


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

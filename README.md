# WireGuard VPN with IdP-driven MFA

A user-authentication layer for WireGuard. Users log in with multi-factor
authentication (password challenge-response, TOTP, FIDO2) gated by a
risk-based engine; on success the gateway provisions WireGuard keys
dynamically and the tunnel comes up. The only root of trust is the gateway's
WireGuard public key — there are no certificates, no CA, no PKI.

> Companion docs: **`RUN.md`** — how to set up and run · **`AUDIT.md`** —
> spec-compliance walkthrough.

---

## Table of contents

1. [What it does](#1-what-it-does)
2. [Components](#2-components)
3. [End-to-end flow](#3-end-to-end-flow)
4. [Trust model](#4-trust-model)
5. [Authentication factors](#5-authentication-factors)
6. [PAM orchestration](#6-pam-orchestration)
7. [Risk-based authentication](#7-risk-based-authentication)
8. [The local HTTP proxy](#8-the-local-http-proxy)
9. [Data layer](#9-data-layer)
10. [Security hardening](#10-security-hardening)
11. [Layout and how to run](#11-layout-and-how-to-run)
12. [Authors](#12-authors)
13. [Features not implemented](#13-features-not-implemented)
14. [Third-party code](#14-third-party-code)

---

## 1. What it does

WireGuard is normally peer-to-peer with pre-shared identity: every peer must
already know the other's public key, the per-peer pre-shared key, and a
routable tunnel IP before the link can come up. This project bolts a login
layer on top so that a user can authenticate to an Identity Provider with
MFA + RBA controls, and have the gateway provision all the per-session
WireGuard parameters automatically.

Conceptually: *"WireGuard with a login screen, backed by an IdP."*

The implementation has three Python processes and one custom C library:

- `UserAuthn` (`client/userauthn.py`) — the login client on the user's host.
- `SrvAuthn` (`server/srvauthn.py`) — the auth proxy and WG provisioner on
  the gateway host.
- `IdP` (`idp/app.py`) — an OAuth 2.0 server (Device Authorization Grant,
  RFC 8628) that drives MFA via PAM.
- A loopback-only `Helpdesk` web UI (`idp/helpdesk/app.py`) for user enrolment
  and credential management.
- `pam_vpnmfa.so` (`idp/pam_iaa/src/pam_vpnmfa.c`) — a custom PAM module
  that decides which factors to require for each login and emits them
  through the standard PAM conversation function.

All three Python processes run as Docker containers; the in-kernel
`wg0` interface lives on the gateway host's network namespace.

---

## 2. Components

```
┌──────────────── client host ─────────────────┐         ┌─────── gateway host ────────┐
│                                              │         │                             │
│  ┌─────────────┐  Noise-IK tunnel (TCP 9999) │         │  ┌──────────────────────┐   │
│  │  UserAuthn  │◄────────────────────────────┤─────────►│  SrvAuthn            │   │
│  │  (Python)   │  {service:auth|proxy}       │         │  │  (network=host)     │   │
│  └──────┬──────┘                             │         │  └───┬──────────┬────┘   │
│         │ local HTTP                         │         │      │ HTTP     │ wg set │
│         │ 127.0.0.1:18080                    │         │      ▼          ▼        │
│         ▼                                    │         │  ┌────────┐  ┌──────┐    │
│   ┌──────────────┐                           │         │  │  IdP   │  │ wg0  │    │
│   │  Browser     │  ── completes MFA via ──  │         │  │ Flask  │  │kernel│    │
│   │              │     OAuth Device Grant    │         │  └───┬────┘  └──────┘    │
│   └──────────────┘                           │         │      │ shared SQLite     │
│                                              │         │      ▼                   │
│      WireGuard tunnel (UDP 51820)            │         │  ┌──────────┐            │
│   ──────────────────────────────────────────►├─────────►│  │ Helpdesk │ 127.0.0.1 │
│                                              │         │  └──────────┘            │
└──────────────────────────────────────────────┘         └─────────────────────────────┘
```

| Process                       | Path                              | Listens on                                   | Talks to                                |
|---                            |---                                |---                                           |---                                      |
| **UserAuthn**                 | `client/userauthn.py`             | `127.0.0.1:18080` (HTTP proxy)               | SrvAuthn on TCP 9999, kernel WG (UDP 51820) |
| **SrvAuthn**                  | `server/srvauthn.py`              | TCP `0.0.0.0:9999`                           | IdP on `localhost:8080`, kernel `wg0`   |
| **IdP**                       | `idp/app.py`                      | TCP `0.0.0.0:8080`                           | shared SQLite                           |
| **Helpdesk**                  | `idp/helpdesk/app.py`             | TCP `127.0.0.1:8081` (loopback only)         | shared SQLite                           |
| **`pam_vpnmfa.so`**           | `idp/pam_iaa/src/pam_vpnmfa.c`    | n/a — loaded by IdP via `libpam`             | PAM conversation function               |
| **WireGuard (`wg0`)**         | in-kernel                         | UDP 51820 on the gateway                     | the kernel                              |

---

## 3. End-to-end flow

```
┌──────────┐                ┌──────────────┐               ┌──────────────────┐              ┌─────────┐
│UserAuthn │                │ SrvAuthn     │               │ IdP (Flask)      │              │ Browser │
└────┬─────┘                └──────┬───────┘               └────────┬─────────┘              └────┬────┘
     │ 1. wg genpsk                                                  │                             │
     │ 2. Noise-IK msg1: e,es,s,ss + {service:auth, user, psk}       │                             │
     │ ───────────────────────►│                                     │                             │
     │ 3. Noise-IK msg2: e,ee,se   (post-handshake AEAD ciphers)     │                             │
     │ ◄───────────────────────│                                     │                             │
     │                         │ 4. POST /oauth/device/code          │                             │
     │                         │ ───────────────────────────────────►│                             │
     │ 5. {user_code, uri} ◄───│ ◄──────── device_code, user_code    │                             │
     │ ◄───────────────────────│                                     │                             │
     │                                                                                             │
     │     ──► opens browser at http://127.0.0.1:18080/oauth/device?code=…  through local proxy    │
     │                                                                                             │
     │                         │                                     │ 6. /device/verify(user_code, username) ◄┐
     │                         │                                     │                                         │
     │                         │                                     │   ├─ compute_risk → score, factors      │
     │                         │                                     │   └─ pam_bridge.start_authentication    │
     │                         │                                     │                                         │
     │                         │                                     │   PAM thread: pam_authenticate(…)       │
     │                         │                                     │     ├─ pam_vpnmfa.so reads IAA_RISK_SCORE
     │                         │                                     │     ├─ tier = L1 / L2 / L3              │
     │                         │                                     │     └─ for each required factor:        │
     │                         │                                     │         conv → "FACTOR:password"        │
     │                         │                                     │           Flask: render proof form      │
     │                         │                                     │           submit_factor_result("OK")    │
     │                         │                                     │         conv → "FACTOR:totp" …          │
     │                         │                                     │                                         │
     │                         │ 7. poll /oauth/token (every 5 s)    │                                         │
     │                         │ ◄─────── access_token (one-shot)    │                                         │
     │                         │ ───────► /oauth/userinfo (Bearer)   │                                         │
     │                         │ ◄─────── {sub, username}            │                                         │
     │                         │                                                                               │
     │                         │ 8. wg genkey | wg pubkey    (server-side)                                     │
     │                         │    lease_next_ip            (atomic, BEGIN IMMEDIATE)                          │
     │                         │    wg set wg0 peer …                                                          │
     │                         │                                                                               │
     │ 9. {client_ip, client_wg_priv, client_wg_pub, server_pubkey, psk}                                       │
     │ ◄───────────────────────│                                                                               │
     │     ──► writes /etc/wireguard/wg0.conf, runs wg-quick up wg0                                            │
     ▼                                                                                                         │
ping 10.10.10.1 succeeds — VPN connected.
```

### 3.1 The auth tunnel

UserAuthn opens a TCP connection to SrvAuthn on port 9999 and runs a
**Noise-IK** handshake against the server's WireGuard public key
(`common/noise.py`, called via `client/tunnel.py`). Noise-IK
authenticates the responder by its long-term static key — which in our
deployment **is** the WireGuard public key the client already knows. After
the two-message handshake the two sides hold a pair of ChaCha20-Poly1305
CipherStates (one per direction) and the rest of the conversation is
length-prefixed encrypted frames (`common/framing.py`).

The first encrypted frame from the client is a JSON envelope that selects
a service:

- `{"service":"auth", "username":…, "psk":…, "interface":"wg0"}` —
  the auth protocol.
- `{"service":"proxy"}` — see §8.

### 3.2 OAuth 2.0 Device Authorization Grant

The IdP implements RFC 8628:

- `POST /oauth/device/code` — start the flow.
- `GET /oauth/device` + `POST /oauth/device/verify` — user submits the
  `user_code` in the browser.
- `POST /oauth/token` — SrvAuthn polls every 5 s.
- `GET /oauth/userinfo` — once the token is granted, SrvAuthn calls this
  with the bearer token to get the user identity.

Access tokens are opaque random strings (48 bytes from
`secrets.token_urlsafe`). The IdP stores their SHA-256 hash, not the raw
token; tokens have a 60 s TTL and are **single-use** — `userinfo` flips
`oauth_tokens.used_at` atomically before returning the response, so any
second call returns `401 invalid_token`.

### 3.3 WireGuard parameter assignment

WireGuard requires six parameters per peer. The spec assigns each one to a
specific side; we follow that assignment literally:

- **Client secret key (param 1)** — SrvAuthn runs `wg genkey | wg pubkey`
  after authentication succeeds and ships the private half down the
  encrypted tunnel as `client_wg_private_key`.
- **Client private tunnel IP (param 2)** — `common/db.py:lease_next_ip`
  picks the lowest free address inside a `BEGIN IMMEDIATE` SQLite
  transaction (so two concurrent provisionings cannot pick the same IP).
- **Pre-shared key (param 6)** — UserAuthn runs `wg genpsk` *before*
  opening the tunnel and sends the result in the hello. SrvAuthn echoes
  the PSK back unchanged; the client refuses to apply a different one.

The server's own WireGuard private key is loaded at startup from
`/etc/wireguard/privatekey-server` and is the same key used by Noise-IK
and by the data plane — one key, two roles.

### 3.4 Lease lifecycle

Every row in `wg_peers` carries an `expires_at` (default lease 24 hours,
configurable via `lease_ttl_seconds` in `srvauthn.conf`). A daemon thread
in SrvAuthn (`server/leases.py`) wakes every `lease_sweeper_poll` seconds
(default 60), finds rows with `expires_at < now AND active = 1`, runs
`wg set <iface> peer <pub> remove`, and marks the DB row inactive.
Provisioning is the only add-path; the sweeper is the only delete-path.

---

## 4. Trust model

The **only** root of trust is the gateway's WireGuard public key — a single
32-byte Curve25519 value. Every UserAuthn instance is given this key
out-of-band (the same way an organisation would hand out a CA bundle today,
except it is one key, not a tree).

That key plays two roles:

1. It is the **Noise-IK responder static key** for the auth tunnel. The
   Noise handshake fails with an AEAD-tag mismatch if the server cannot
   prove possession of the matching private key.
2. It is the WireGuard data-plane static key the kernel uses once the
   tunnel is provisioned.

There are no TLS certificates, no CAs, no certificate-revocation lists.
The browser-facing side reaches the IdP through a local HTTP proxy that
re-uses the same Noise-IK tunnel (see §8), so the browser's trust anchor
is the same WG public key — no additional certificate to install.

---

## 5. Authentication factors

Three factors are implemented, in robustness order (least → most):

### 5.1 Password — challenge-response

The raw password never leaves the browser. The flow:

```
Enrolment (helpdesk):
    salt     = os.urandom(16)
    verifier = scrypt(password, salt, N=2^14, r=8, p=1)        # 32 bytes
    store (salt, verifier)

Login (IdP):
    GET  /oauth/mfa/<sid>/password/challenge
                                ──► {salt, nonce_32, scrypt params}
    Browser computes  verifier' = scrypt(password, salt)
    proof = HMAC-SHA256(verifier', nonce)
    POST /oauth/mfa/<sid>/password {proof}
                                ──►  expected = HMAC-SHA256(verifier, nonce)
                                     constant_time_eq(expected, proof) ?
                                     mark nonce_consumed = 1
```

Browser-side scrypt is `idp/static/js/scrypt.js` (RFC 7914 over the
WebCrypto PBKDF2-HMAC-SHA256 primitive). The HMAC step uses
`crypto.subtle.sign('HMAC', …)`. Server side, `hashlib.scrypt` and `hmac`
are both stdlib.

The `mfa_sessions.password_nonce` is single-use — `consume_password_nonce`
runs inside `BEGIN IMMEDIATE` so a replayed `(nonce, proof)` pair finds
the nonce already consumed.

### 5.2 TOTP

RFC 6238 (six digits, 30 s window, ±1 step tolerance) via `pyotp`. The
shared secret is stored **encrypted at rest** with AES-256-GCM (see §10.3).

### 5.3 FIDO2 / WebAuthn

Backed by the `webauthn>=2.0` library. Both registration (helpdesk) and
authentication (IdP) request `UserVerificationRequirement.REQUIRED`, so
the authenticator must enforce a local check (PIN / biometric) and the
server validates the `uv` flag in the assertion. A stolen, unlocked
security key cannot satisfy the factor.

---

## 6. PAM orchestration

The factor sequence is decided by a custom **PAM module** loaded into the
IdP process, not by Python.

### 6.1 The flow

When the user submits their username at `/oauth/device/verify`, the IdP:

1. Computes a risk score (`idp/rba.py:compute_risk`).
2. Calls `pam_bridge.start_authentication(sid, username, ip, score)`
   (`idp/pam_bridge.py`) which spawns a worker thread.
3. The thread opens a PAM context through the ctypes wrapper in
   `common/libpam.py` and calls `pam_authenticate("iaa-vpn", username)`.
4. libpam loads `/etc/pam.d/iaa-vpn`, which contains a single
   `auth required pam_vpnmfa.so` line, so our custom module is the
   orchestrator.
5. `pam_vpnmfa.so` reads `pam_getenv("IAA_RISK_SCORE")`, maps it to a
   tier, then emits one PAM conversation message per required factor of
   the form `FACTOR:<name>`.

### 6.2 The conversation contract

The PAM module talks to the Python bridge through the standard PAM
conversation function. Two message styles are used:

| Style                 | Message payload   | Expected response                |
|---                    |---                |---                               |
| `PAM_PROMPT_ECHO_OFF` | `FACTOR:password` / `FACTOR:totp` / `FACTOR:fido2` | `OK` / `FAIL` / `UNAVAILABLE` |
| `PAM_TEXT_INFO`       | `INFO:tier=L2 score=30` (and similar)              | (any string, treated as ack)  |

`OK` lets the C module advance to the next factor; `FAIL` returns
`PAM_AUTH_ERR`; `UNAVAILABLE` returns `PAM_AUTHINFO_UNAVAIL`.

The Python bridge parks the conv callback on a `threading.Event`. The
browser GETs `/oauth/mfa/<sid>`, which calls `wait_for_prompt(sid)` and
renders the corresponding factor template. When the user submits the
factor, the Flask route verifies it and calls `submit_factor_result(sid,
"OK"|"FAIL"|"UNAVAILABLE")`, the event fires, the conv returns, and the
C module continues with the next factor or returns success.

### 6.3 Tier mapping

The C module enforces this mapping directly:

```c
score <  30   →  L1: password
score <  60   →  L2: password + TOTP
score >= 60   →  L3: password + TOTP + FIDO2
```

The C module always asks for factors in `[password, totp, fido2]` order —
matching the spec's "least robust → most robust" ordering.

---

## 7. Risk-based authentication

`idp/rba.py:compute_risk(username, ip, user_agent)` aggregates four signals,
all from data already in the local database — no external HTTP calls:

| Signal                              | Penalty                | Where it comes from              |
|---                                  |---                     |---                               |
| First-ever login for this user      | +0.30                  | `rba_ip_history` is empty        |
| New IP for an existing user         | +0.20                  | IP not in `rba_ip_history`       |
| Recent failures (last 30 min)       | +0.10 each, max +0.40  | `rba_events`                     |
| Unusual hour (00:00–06:00 UTC)      | +0.20                  | `datetime.now().hour`            |

The float score is clamped to `[0, 1]` and scaled to `0–100` for the PAM
module. The label `L1/L2/L3` follows from the tier thresholds above.

If the chosen tier requires a factor the user is not enrolled for,
`compute_risk` returns `factors=None` and the IdP renders a 403 *"contact
your helpdesk"* page. There is no silent downgrade to a weaker tier.

---

## 8. The local HTTP proxy

To keep the browser flow on the same trust anchor as the auth tunnel, the
browser does not reach the IdP directly. Instead:

- UserAuthn opens a TCP listener on `127.0.0.1:18080` (`client/proxy.py`).
- For every browser connection accepted there, UserAuthn opens a *new*
  Noise-IK tunnel to SrvAuthn and sends `{"service":"proxy"}` as the
  first encrypted frame.
- `server/proxy.py:handle_proxy` opens a TCP connection to the IdP at
  `localhost:8080` and pumps bytes both ways for the lifetime of the
  browser connection.

The IdP's `ORIGIN` is set to `http://127.0.0.1:18080`, so the
`verification_uri_complete` it generates is
`http://127.0.0.1:18080/oauth/device?code=…`. The browser opens that;
traffic flows over Noise; the user never sees the gateway address.
WebAuthn's `RP_ID=127.0.0.1` covers both the proxy origin and the
helpdesk's `http://127.0.0.1:8081`, so credentials registered on the
helpdesk validate at the IdP unchanged.

---

## 9. Data layer

Single SQLite database at `/data/vpnauth.db` (WAL mode, foreign keys on),
shared between the IdP and the helpdesk via a bind-mount. Schema is
declared in `common/db.py:init_db` and carries a version marker; a
mismatched persisted DB is wiped and recreated on startup.

Tables of note:

| Table                | Notable columns                                                                                  |
|---                   |---                                                                                               |
| `users`              | `username`, `failed_attempts`, `locked_until`, `last_failure_at`                                  |
| `passwords`          | `salt BLOB`, `verifier BLOB` (scrypt verifier)                                                    |
| `totp_secrets`       | `secret_enc BLOB` (AES-256-GCM ciphertext), `confirmed`                                           |
| `fido2_credentials`  | `cred_id`, `public_key`, `sign_count`, `transports`                                               |
| `oauth_clients`      | `client_id`, `client_secret`                                                                      |
| `device_codes`       | `device_code`, `user_code`, `status`, `expires_at`                                                |
| `oauth_tokens`       | `token_hash` (SHA-256), `used_at`, `expires_at`                                                   |
| `mfa_sessions`       | `session_id`, `required_factors`, `password_ok`/`totp_ok`/`fido2_ok`, `password_nonce`            |
| `rba_events`         | `event_type`, `success`, `ip_address`, `risk_score`, `factors_used`                               |
| `rba_ip_history`     | `user_id`, `ip_address`, `count`                                                                  |
| `wg_peers`           | `user_id`, `interface`, `client_pubkey`, `client_ip`, `psk`, `active`, `expires_at`               |
| `schema_version`     | `version`                                                                                         |

Three operations take `BEGIN IMMEDIATE` to avoid races:

- `lease_next_ip` — atomic find-free-IP + insert peer.
- `consume_password_nonce` — atomic challenge-response nonce burn.
- `mark_token_used` — atomic single-use OAuth-token flip.

---

## 10. Security hardening

### 10.1 OAuth tokens

Stored as `SHA-256(token)` (not plaintext), 60 s TTL, single-use (`used_at`
flipped atomically). A DB backup leaks zero usable tokens.

### 10.2 Account lockout

Five failed factor verifications inside a 5-minute window lock the account
for 15 minutes. The lockout check runs at the top of every `mfa_*` route
before any cryptographic work, so brute-force attempts are cheap to refuse.
On a fully successful login the counter resets to zero. Per-account (not
per-IP) so an attacker can't bypass the lockout by rotating IPs; the
lockout window does not extend on additional failures during the lock, so
it can't be weaponised into DoS.

### 10.3 TOTP secrets encrypted at rest

Stored as `nonce(12) || ciphertext || tag(16)` under AES-256-GCM. The key
(`IAA_MASTER_KEY`) is a 32-byte base64 value loaded from the environment;
`common/config.py:require_master_key` validates length and decoding at
startup and refuses to launch with a missing or placeholder value.

### 10.4 Fail-closed configuration

`common/config.py:require_env(name)` exits 78 if the named variable is
missing, empty, or contains a placeholder substring like `change-me` or
`REPLACE_OR`. All three Python entry points call it at module load.

### 10.5 WireGuard key validation

The client-supplied PSK in the hello is base64-decoded and length-checked
to exactly 32 bytes; anything else returns `{"error":"invalid_psk"}` before
the value is passed to `wg set`.

### 10.6 Helpdesk loopback-only

The helpdesk binds `127.0.0.1:8081` and its container runs in
`network_mode: host`, so the bind is literally the host's loopback. The
helpdesk is unreachable from off-host.

---

## 11. Layout and how to run

```
client/          # runs on the user's host
  userauthn.py     login client, kicks off the Noise-IK tunnel
  tunnel.py        TunnelSession + connect() initiator
  proxy.py         local HTTP proxy at 127.0.0.1:18080
  base.conf.example

server/          # runs on the gateway host
  srvauthn.py      Noise responder; auth + WG provisioning
  tunnel.py        accept_handshake()
  proxy.py         tunnel ↔ localhost:8080 pump
  leases.py        background sweeper for expired peers
  entrypoint.sh    Docker entrypoint: bring up wg0, then srvauthn
  srvauthn.conf.example

idp/             # the IdP
  app.py                       OAuth Device Grant + MFA routes
  pam_bridge.py                drives pam_authenticate in a worker thread
  rba.py                       risk score and factor selection
  pam_iaa/
    src/pam_vpnmfa.c           the custom PAM module
    pam.d/iaa-vpn              PAM service profile
    Makefile                   builds pam_vpnmfa.so
  helpdesk/
    app.py                     enrolment UI (loopback only)
    templates/                 HTML
    static/js/webauthn.js
  templates/                   HTML
  static/js/
    scrypt.js                  pure-JS scrypt for the password CR step
    password_cr.js             builds and POSTs the HMAC proof
    webauthn.js                FIDO2 client glue

common/          # shared by all three apps
  db.py            SQLite schema, helpers, AES-GCM, atomic helpers
  config.py        require_env, require_master_key
  libpam.py        ctypes wrapper over libpam.so.0
  framing.py       length-prefixed framing
  noise.py         Noise-IK over cryptography.hazmat (Curve25519 +
                   ChaCha20Poly1305 + BLAKE2s)

scripts/
  init-wg.sh       generate server WG keypair
  setup.py         one-command setup
  test_e2e.py      full VM end-to-end test
  teardown.py      stop / reset / remove-VM

docker-compose.yml
.env.example
ProjectSpec.pdf
README.md
RUN.md
AUDIT.md
```

To run the stack from a clean clone:

```bash
python3 scripts/setup.py        # one-time, idempotent
python3 scripts/test_e2e.py     # full VPN bring-up + ping (Multipass VM)
```

The full guide — prerequisites, manual browser demo, teardown levels,
common pitfalls — is in [`RUN.md`](RUN.md).

---

## 12. Authors

| Number | Name | Contribution |
|---     |---   |---           |
| _____  | _____ | _____ % |
| _____  | _____ | _____ % |
| _____  | _____ | _____ % |

---

## 13. Features not implemented

- **RBA — "Autonomous Service" indicator.** The project specification lists
  *"same/different Autonomous Service"* as one of the example RBA signals
  to consider, alongside IP, recent failures, and time of day. The first
  and last three are implemented (see §7); the Autonomous-Service signal
  is not. Resolving it would require either bundling a GeoIP/AS database
  (~50 MB of binary data) or querying an external service on every login
  (privacy leak + external dependency for a system whose whole point is a
  closed trust model). The remaining three indicators give the RBA engine
  enough discrimination to drive the L1/L2/L3 tiering meaningfully.

Everything else mentioned in the project specification is implemented.
A line-by-line walkthrough is in [`AUDIT.md`](AUDIT.md).

---

## 14. Third-party code

Original work:

- The Noise-IK implementation in `common/noise.py`, written from RFC and
  the Noise spec (revision 34) against the lower-level
  `cryptography.hazmat` primitives only (no third-party Noise library).
- The browser-side scrypt in `idp/static/js/scrypt.js`, written from
  RFC 7914 over the WebCrypto PBKDF2-HMAC-SHA256 primitive.
- The PAM orchestrator in `idp/pam_iaa/src/pam_vpnmfa.c`, linking only
  against libpam.
- The ctypes wrapper in `common/libpam.py`.
- Everything else in `client/`, `server/`, `idp/`, `common/`, and
  `scripts/`.

External libraries used (acknowledged here per the spec's plagiarism rules):

| Library                   | Used by                                  | Purpose                                                    |
|---                        |---                                       |---                                                          |
| `flask`                   | IdP, helpdesk                            | HTTP server                                                 |
| `pyotp`                   | IdP, helpdesk                            | TOTP generation / verification (RFC 6238)                   |
| `webauthn` (v2+)          | IdP, helpdesk                            | WebAuthn / FIDO2 verification                               |
| `qrcode[pil]`, `pillow`   | helpdesk                                 | QR codes for TOTP enrolment                                 |
| `cryptography`            | IdP, helpdesk, SrvAuthn, common          | X25519, ChaCha20-Poly1305, AES-256-GCM, BLAKE2s, PBKDF2     |

System tools invoked by subprocess: `wg`, `wg-quick`, `wg genkey`,
`wg pubkey`, `wg genpsk` (WireGuard userspace tools).

The libpam C library is loaded at runtime via `ctypes`. Linux's PAM stack
itself is shipped with the OS; we install a service profile
(`/etc/pam.d/iaa-vpn`) and a custom module (`pam_vpnmfa.so`) into the
standard PAM module directory.

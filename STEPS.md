# Implementation Plan — from current state to spec-aligned

> Concrete, ordered steps to take the project from where it is today to a working, spec-aligned implementation.
> **Test procedures, verification steps, and checklists: see `RUNBOOK.md`.**
>
> Out of scope (deliberately deferred):
> - Final `README.md` / project report (written after code is done).
> - Bonus features from `DESIGN.md` §9.
>
> Pre-reading order: `PROJECT_UNDERSTANDING.md` → `DESIGN.md` → `AUDIT.md` → this file.

---

## 0. Critical path at a glance

```
  Phase 0   Get baseline running
     │              (1 day, all hands)
     ▼
  Phase 1   Spec fixes + security hardening
     │              (3 days, B + C in parallel)
     ▼
     ├──► Phase 2   PAM orchestration refactor   (2–3 days, C)
     │
     └──► Phase 3   Noise-IK tunnel + HTTP proxy (3–4 days, A)
     │
     ▼        (Phases 2 and 3 are independent — run in parallel)
  Phase 4   Lease expiry, TOTP encryption, cleanup, full E2E
                (1.5 days, all hands)
```

Owners refer to `DESIGN.md` §10:

- **A** — tunnel/transport plumbing
- **B** — UserAuthn ↔ SrvAuthn glue + WG integration
- **C** — IdP, MFA factors, PAM, RBA

With three people working in parallel where possible, the wall-clock estimate is ~7–9 days.

---

## Phase 0 — Get the baseline running

**Goal:** before changing anything, get the *current* (TLS-based, Python-orchestrated-MFA) version running end-to-end on one development machine. This gives a known-working reference to compare every later change against, and surfaces environment problems (Linux/Docker/PAM/WG-headers) early.

**Owner:** B drives, A and C help debug.

**Time:** half a day to one day depending on environment surprises.

| # | Step | Files | Done when |
|---|---|---|---|
| 0.1 | Decide where `wg0` lives in the dev deployment. Two viable options: **(a)** drop the `linuxserver/wireguard` container and run `wg0` directly inside the SrvAuthn container (SrvAuthn already has `network_mode: host` + `NET_ADMIN`); **(b)** keep WG on the host (`apt install wireguard-tools`, `wg-quick up wg0`). Recommendation: **(a)** — keeps everything in compose. | `docker-compose.yml` decision; no code change yet. | Decision recorded in `docker-compose.yml` comments. |
| 0.2 | Update `docker-compose.yml`: remove the `wireguard:` service, install `wireguard-tools` + `iproute2` in the SrvAuthn `Dockerfile`, and bind-mount `./wireguard/` at `/etc/wireguard/`. Make SrvAuthn bring `wg0` up on startup via a new `server/entrypoint.sh`. | `docker-compose.yml`, `server/Dockerfile`, `server/entrypoint.sh` (new). | `docker compose up -d --build` succeeds; `docker exec vpn-srvauthn wg show wg0` lists the interface. |
| 0.3 | Generate the server's WG keypair + initial `wg0.conf` (no peers yet). Save the private key to `./wireguard/privatekey-server` and the public key to `./wireguard/publickey-server`. | `./wireguard/wg0.conf` (gitignored), `server/srvauthn.conf.example`. | `wg show wg0` shows the server interface on UDP 51820, no peers. |
| 0.4 | Generate a TLS cert for SrvAuthn (`bash scripts/init-certs.sh`). Phase 3 replaces this with Noise-IK; Phase 0 needs it to function. | `./certs/srv.{key,crt}` (gitignored). | `openssl s_client -connect localhost:9999` shows the cert. |
| 0.5 | Enrol a test user via the helpdesk at `http://localhost:8081`. Create user, set password, generate + confirm TOTP. | none (data in SQLite DB). | User shows green check-marks for password and TOTP. |
| 0.6 | Run the end-to-end client flow from a client VM. | `client/base.conf` (filled from example). | `ping 10.10.10.1` succeeds from inside the tunnel. |
| 0.7 | Write `RUNBOOK.md` so any team-mate can repeat steps 0.2–0.6 from a clean clone. | `RUNBOOK.md`. | **Done** — see `RUNBOOK.md`. |

---

## Phase 1 — Easy spec-compliance fixes

**Goal:** clear the small, isolated spec deviations before the two big refactors land. Each item here is touched-by-one-person, can be tested independently, and unblocks no one.

**Owner:** B does 1.1, 1.2, 1.3, 1.11, 1.13. C does 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10. 1.12 is shared (touches IdP, SrvAuthn, and helpdesk).

**Time:** ~3 days.

### 1.1 Flip WG client-parameter generation (per spec §3)

- **Why:** spec §3 assigns each WG client parameter to a specific side: PSK (param 6) → client-generated; secret key (param 1) and private IP (param 2) → server-provided. The current code reverses two of the three — `server/srvauthn.py:244` generates the PSK; `client/userauthn.py:generate_wg_keypair` generates the client's WG keypair.
- **Server-side (`server/srvauthn.py`):**
  - **Generate the client's WG keypair** after authentication succeeds: run `wg genkey` + `wg pubkey` server-side; keep the *public* key for `wg set ... peer ...`; send the *private* key down to the client over the tunnel.
  - **Stop generating the PSK.** Read it from the client's hello message; validate it (base64-decodes to exactly 32 bytes).
- **Client-side (`client/userauthn.py`):**
  - **Stop generating the WG keypair.** Delete `generate_wg_keypair`. Accept `client_wg_private_key` in the server's response and write it into the local `wg0.conf`.
  - **Generate the PSK** at session start (`wg genpsk`) and include it in the hello message.
- **JSON message changes:**
  - C→S hello adds `psk` (base64) and `interface`.
  - S→C success response adds `client_wg_private_key` and `client_wg_public_key` (base64).
- **DB:** `common/db.py:upsert_wg_peer` already takes `psk`; no schema change needed.

### 1.2 Reference the server WG **private** key in the SrvAuthn config

- **Why:** spec §2 says SrvAuthn's base config includes its *secret* key (parameter 1). Currently `server/srvauthn.conf.example` only has the public key.
- **Edit:** `server/srvauthn.conf.example` — add `wg_private_key_file = /etc/wireguard/privatekey-server`.
- **Edit:** `server/srvauthn.py` — at startup, read that file and log "loaded server WG private key (fingerprint: …)". Store as `cfg["server"]["wg_private_key"]` for Phase 3 to consume. If the file is missing, log a clear error and exit cleanly.

### 1.3 Remove the silent `CERT_NONE` fallback

- **Why:** `client/userauthn.py:76–79` silently disables certificate verification if `tls_cert` is missing. Security bug regardless of Phase 3 replacing TLS.
- **Edit:** if `tls_cert` is missing or unreadable, **fail with a clear error** ("server TLS certificate not found at … — refusing to connect"). No fallback.

### 1.4 Tighten the RBA fallback policy

- **Why:** `idp/rba.py` currently falls back to whatever factors the user happens to have enrolled — so a HIGH-risk login by a user with only a password can succeed with just a password. That defeats RBA tiering.
- **Edit:** `idp/rba.py` — implement the policy from `DESIGN.md` §5.2:
  - L1 (low risk): require **password**.
  - L2 (medium risk): require **password + TOTP**. If user has no TOTP → **reject**.
  - L3 (high risk): require **password + TOTP + FIDO2**. If user has no FIDO2 → **reject**.
- **Add:** a `compute_risk()` exit path that returns `factors=None, reason="missing factor: …"` and surfaces an error page ("contact your helpdesk to enrol additional factors").

### 1.5 Drop the online ASN lookup

- **Why:** `idp/rba.py:_get_asn_info` calls `http://ip-api.com/json/<ip>` synchronously. Privacy concern, rate-limit concern, offline-demo concern.
- **Choose one of two options:**
  - **A (recommended):** bundle MaxMind ASN GeoLite2 database + `python-geoip2`. Add file under `./data/`, dependency to `idp/requirements.txt`.
  - **B (zero-effort):** drop the ASN signal. Document in `JUSTIFICATIONS.md` §2 that we dropped it; keep IP-change and time-of-day signals.
- **Update** `DESIGN.md` §5.2 RBA factor table to match whichever option you chose.

### 1.6 Implement password challenge-response

- **Why:** spec §3 says **"password-based (challenge-response-based)"**. Current code POSTs the raw password.
- **Design (document in `JUSTIFICATIONS.md` §3):**
  - Replace bcrypt with **scrypt(password, salt) → 32 B verifier**. Store `(salt, verifier)` in `passwords` table.
  - Login flow:
    1. Browser GETs `/oauth/mfa/<sid>/password` — server returns page with a random 32 B nonce in a hidden field and the user's `salt`.
    2. JS computes `verifier = scrypt(password, salt)`, then `proof = HMAC-SHA256(verifier, nonce)`, POSTs only `proof`.
    3. Server computes `expected = HMAC-SHA256(stored_verifier, nonce)`, compares in constant time. Sets `mfa_sessions.nonce_consumed = 1`. Replay rejected.
  - Use `scrypt-js` (single .js file ~10 KB). Parameters: `N=2^14, r=8, p=1`.
- **Edits:** `idp/templates/mfa.html`, `idp/static/js/password_cr.js` (new), `idp/app.py:mfa_password()`, `common/db.py` schema (`salt` + `verifier` columns), `idp/helpdesk/app.py:set_password()`.
- **Schema:** add `password_nonce` (BLOB) and `nonce_consumed` (INTEGER) to `mfa_sessions`.

### 1.7 Bind the helpdesk to `127.0.0.1`

- **Why:** spec says the helpdesk is "internal and exclusive". Currently listens on `0.0.0.0:8081`.
- **Edit:** `idp/helpdesk/app.py:app.run(host="0.0.0.0", …)` → `host="127.0.0.1"`.

### 1.8 Harden OAuth access tokens (hashing, TTL, single-use)

- **Why:** `idp/app.py:token()` stores tokens in plaintext with `TOKEN_TTL = 3600`. Three issues: DB leak hands attacker every live session; TTL far too long; tokens are reusable.
- **Fixes:**
  - **Hash at rest.** Rename column `access_token` → `token_hash`; store `hashlib.sha256(token.encode()).hexdigest()`. Touch points: `common/db.py`, `idp/app.py:token()`, `idp/app.py:userinfo()`.
  - **Short TTL.** Reduce `TOKEN_TTL` from `3600` to `60`.
  - **Single-use.** Add `used_at` column. In `userinfo()`: if `used_at IS NOT NULL` → `401 invalid_token`. Otherwise set `used_at = now` *before* returning user data.
- **Justification:** `JUSTIFICATIONS.md` §4.

### 1.9 FIDO2: require user verification

- **Why:** both the helpdesk registration and the IdP authentication pass `UserVerificationRequirement.PREFERRED`. A stolen unlocked YubiKey without PIN/biometric would pass.
- **Fix:** change both call sites to `UserVerificationRequirement.REQUIRED` — in `idp/helpdesk/app.py:fido2_register_start` and `idp/app.py:mfa_fido2_start`.
- **Justification:** `JUSTIFICATIONS.md` §6.

### 1.10 Rate-limit factor verifications + account lockout

- **Why:** TOTP has only 10⁶ possible codes; there is no rate limiting on any factor verification route.
- **Design:**
  - Add to `users`: `failed_attempts INTEGER DEFAULT 0`, `locked_until INTEGER DEFAULT 0`.
  - On every factor failure: increment `failed_attempts`. If it reaches 5 within the last 5 minutes: set `locked_until = now + 900`, reset counter to 0.
  - At the *start* of every factor route: check `locked_until > now`; if so, render "account temporarily locked" page.
  - On full successful authentication: reset `failed_attempts = 0`.
- **Justification:** `JUSTIFICATIONS.md` §7.

### 1.11 Make IP allocation race-safe

- **Why:** `server/srvauthn.py:allocate_ip` reads used IPs, picks the lowest free, and writes. Between read and write, a concurrent request can pick the same IP.
- **Fix:** wrap read-pick-write in a `BEGIN IMMEDIATE` SQLite transaction. Move into `common/db.py:lease_next_ip(interface, subnet, user_id, ...)` that performs the whole sequence atomically and raises `NoFreeIPError` if the subnet is exhausted.

### 1.12 Fail-closed configuration

- **Why:** `idp/app.py` and `idp/helpdesk/app.py` fall back to default secret values if env vars are missing. A misconfigured deployment runs silently with known-weak secrets.
- **Fix:** at process start in each of the three apps (IdP, SrvAuthn, helpdesk), check that required env vars (`SECRET_KEY`, `OAUTH_CLIENT_SECRET`, and `IAA_MASTER_KEY` once introduced in 4.6) are set, non-empty, and **not** equal to any `change-me-*` placeholder. Log a clear error and exit non-zero if any check fails. Add a small helper in `common/config.py` for the shared check.
- **Update** `.env.example`: rename placeholders to obvious sentinels like `REPLACE_OR_THE_APP_WILL_REFUSE_TO_START`.

### 1.13 Validate WG public key before `wg set`

- **Why:** `server/srvauthn.py:register_wg_peer` passes the client-provided pubkey straight to `wg set`. Not exploitable as command injection (list-form subprocess), but a malformed string produces confusing `wg` errors.
- **Fix:** after parsing the hello message, validate `client_pubkey`: must base64-decode to exactly 32 bytes. Reject with `{"error": "invalid_client_pubkey"}` otherwise.

---

## Phase 2 — PAM orchestration refactor (Issue #1)

**Goal:** make `pam_iaa.so` the actual orchestrator. The IdP calls `pam_authenticate()`; the C module reads RBA inputs, decides which factors to require, and drives those factors back through the conversation function.

**Owner:** C, with B available for the wg-side glue if needed.

**Time:** 2–3 days.

### The shape of the new control flow

```
  Browser POSTs username      Flask /oauth/device/verify
                                 │
                                 ▼
                          start thread → libpam.pam_authenticate("iaa-vpn",
                                                                  username,
                                                                  conv=conv_fn(sid))
                                 │                       │
                                 │                       ▼
                                 │            pam_iaa.so:pam_sm_authenticate
                                 │                       │
                                 │            reads PAM items: PAM_USER,
                                 │            PAM_RHOST, "iaa_risk_score"
                                 │                       │
                                 │            decides L1/L2/L3
                                 │                       │
                                 │     for each required factor:
                                 │                       │
                                 │            calls conv with prompt
                                 │            "FACTOR:password" / "FACTOR:totp"
                                 │            / "FACTOR:fido2"
                                 │                       │
                                 ▼            conv_fn(sid) blocks on a
              Flask handler returns 302       threading.Event tied to <sid>;
              to /oauth/mfa/<sid>             stashes the prompt in a shared dict
                                 │
                                 ▼
                          Browser GETs /oauth/mfa/<sid>
                          → reads pending prompt → redirects to factor page
                                 │
                                 ▼
                          User completes factor → route POSTs result,
                          sets Event, conv_fn unblocks → returns response to PAM
```

| # | Step | Files | Done when |
|---|---|---|---|
| 2.1 | **Pick a libpam binding strategy.** Recommendation: **(a)** `ctypes` wrapper we write (~80 lines) — transparent and no extra deps. Alternatively: **(b)** `pamela` PyPI package. **Not:** `python-pam` (doesn't support custom conv). | `common/libpam.py` (if a), or `idp/requirements.txt` (if b). | A small Python script calls `pam_authenticate()` against the default `login` service with a working conv. |
| 2.2 | **Define the conversation contract.** Document at the top of `idp/pam_bridge.py`: prompts `pam_iaa.so` will send (`FACTOR:password`, `FACTOR:totp`, `FACTOR:fido2`, `INFO:<text>`) and response format (`OK` / `FAIL` / `UNAVAILABLE`). | `idp/pam_bridge.py` docstring. | Unambiguous enough for A and B to read without asking C. |
| 2.3 | **Write `idp/pam_bridge.py`.** Public surface: `start_authentication(session_id, username, ip, risk_score)`; `wait_for_prompt(session_id, timeout)`; `submit_factor_result(session_id, "OK"\|"FAIL"\|"UNAVAILABLE", payload)`; `get_result(session_id) → True/False`. Internals: per-session dict with two `threading.Event`s + a thread running `pam_authenticate()`. | `idp/pam_bridge.py` (new). | Unit test: start an auth, observe `FACTOR:password` prompt, submit `OK`, get successful result. |
| 2.4 | **Rewrite `idp/pam_iaa/src/pam_vpnmfa.c` as the orchestrator.** Must: (i) read `PAM_USER`, `PAM_RHOST`, custom item `iaa_risk_score`; (ii) decide L1/L2/L3 (thresholds live in C, score passed in from Python); (iii) call conv once per required factor; (iv) return `PAM_SUCCESS` / `PAM_AUTH_ERR` / `PAM_AUTHINFO_UNAVAIL`. **Drop** all libcurl/JSON/HTTP logic — that path is dead. | `idp/pam_iaa/src/pam_vpnmfa.c` (major rewrite). | `pamtester iaa-vpn <user> authenticate` with mock conv returning "OK" three times succeeds. |
| 2.5 | **Adjust the PAM service config.** Drop the `idp_url=` argument — the module no longer calls back over HTTP. | `idp/pam_iaa/pam.d/iaa-vpn`. | Module loads with no `idp_url` and authenticates correctly. |
| 2.6 | **Refactor `idp/app.py:mfa_*` routes.** Each factor route does verification + signalling only, not sequencing. `/oauth/mfa/<sid>` GET reads from `pam_bridge.wait_for_prompt(sid)`, renders the right page. `/oauth/mfa/<sid>/<factor>` POST verifies and calls `pam_bridge.submit_factor_result(...)`. `_complete_auth` triggers when `pam_bridge.get_result()` is `True`. | `idp/app.py`. | Full L2 (password + TOTP) login through the browser works; PAM thread visible in IdP log. |
| 2.7 | **Compute RBA score in `idp/rba.py`, pass into PAM as a custom item, decide level inside C.** Python returns score (0–100) + metadata for logging. C maps score → level. | `idp/rba.py`, `idp/pam_bridge.py`, `idp/pam_iaa/src/pam_vpnmfa.c`. | Three logins with synthetic risk scores 10, 40, 80 demand password, password+TOTP, password+TOTP+FIDO2. |
| 2.8 | **Delete `idp/pam_routes.py`** and remove its import from `idp/app.py`. | `idp/app.py`, `idp/pam_routes.py` (deleted). | `grep -ri "pam_routes\|/pam/factors\|/pam/verify"` returns no source-code hits. |
| 2.9 | **Test end-to-end** with TLS tunnel still in place (Phase 3 not yet done). | none new. | Phase 0 smoke test still works, but MFA is now orchestrated by PAM. |

---

## Phase 3 — Noise-IK tunnel + HTTP proxy (Issue #2)

**Goal:** replace the TLS-with-distributed-cert transport with a Noise-IK handshake keyed on the server's WireGuard public key. Add the HTTP proxy (browser → localhost:N → tunnel → IdP) that the spec recommends.

**Owner:** A, with B for the UserAuthn/SrvAuthn integration once tunnel + proxy exist.

**Time:** 3–4 days.

| # | Step | Files | Done when |
|---|---|---|---|
| 3.1 | **Write `common/framing.py`.** Length-prefixed framing: `[u32 length BE][payload bytes]`. `send_frame(sock, bytes)` and `recv_frame(sock) → bytes` with a 64 KiB hard cap. | `common/framing.py` (new). | Property test: round-trip 10 000 random byte strings. |
| 3.2 | **Write `common/noise.py`.** Implement Noise-IK over Curve25519 + ChaCha20-Poly1305 + BLAKE2s using `cryptography.hazmat.*` only. **No third-party Noise library.** Reference: noiseprotocol.org §7, §8, §13. Public surface: `NoiseHandshake.initiator(server_static_pub)`, `.responder(local_static_priv)`, `.write_message(payload) → bytes`, `.read_message(data) → payload`, `.finalize() → (cipher_send, cipher_recv)`. | `common/noise.py` (new). | Test vectors from Noise spec §13.2 (IK pattern) pass. |
| 3.3 | **Write `client/tunnel.py` and `server/tunnel.py`.** Thin wrappers: server listens on TCP `auth_port`, runs responder handshake on each accept using its long-lived WG private key, returns a `TunnelSession` with `.send(bytes) / .recv() → bytes` using post-handshake ciphers + framing. Client is the initiator. | `client/tunnel.py`, `server/tunnel.py` (new). | Two loopback scripts: client sends "hello", server replies "world". |
| 3.4 | **Wire the tunnel into UserAuthn ↔ SrvAuthn.** Replace `connect_to_srvauthn` (TLS) in `client/userauthn.py` with `tunnel.connect(...)`. Replace the TLS server in `server/srvauthn.py:run_server` with the Noise responder. JSON message shapes stay the same. | `client/userauthn.py`, `server/srvauthn.py`. | Phase 1 E2E still works; `tcpdump -X port 9999` shows random-looking bytes from byte one (no TLS handshake). |
| 3.5 | **Add the local HTTP proxy on the client.** UserAuthn opens a TCP listener on `127.0.0.1:18080`. For each browser connection, open a new tunnel sub-stream to SrvAuthn and pipe bytes both ways. | `client/proxy.py` (new), `client/userauthn.py`. | `curl http://127.0.0.1:18080/health` returns the IdP's `/health` JSON. |
| 3.6 | **Add the proxy egress on the server.** SrvAuthn receives proxied bytes from the tunnel, opens a TCP connection to `localhost:8080` (IdP), pipes both ways. | `server/proxy.py` (new), `server/srvauthn.py`. | Same `curl` test from the *client host* hits the IdP via the tunnel. |
| 3.7 | **Update the verification URI.** SrvAuthn returns `http://127.0.0.1:18080/oauth/device?code=…` (user's local proxy port) instead of the IdP's direct address. | `server/srvauthn.py:handle_client`. | Browser opens `localhost:18080`, completes MFA, all over the tunnel. |
| 3.8 | **Verify with FIDO2.** Set `RP_ID=127.0.0.1` and `ORIGIN=http://127.0.0.1:18080` in `.env.example`. (WebAuthn cares about origin — this is the most common stumbling block after step 3.7.) | `.env.example`, `docker-compose.yml`. | FIDO2 registration via helpdesk and FIDO2 login through the proxy both succeed. |
| 3.9 | **Delete the TLS scaffolding.** Remove `tls_cert`, `tls_key` from `server/srvauthn.conf.example` and `client/base.conf.example`. Remove SSL setup in `client/userauthn.py`. Drop `certs/` from the repo. | several. | `grep -ri "ssl\|tls\|certs/\|srv\.crt"` in `client/`, `server/`, `common/` returns no hits except docs. |

---

## Phase 4 — Lease expiry, cleanup, full end-to-end

**Goal:** add the one missing operational feature (lease expiry), do a final integration pass, and confirm every spec line item is satisfied.

**Owner:** all three, ~1.5 days.

| # | Step | Files | Done when |
|---|---|---|---|
| 4.1 | **Add `expires_at` to `wg_peers`.** Schema migration in `common/db.py`. When SrvAuthn provisions a peer, write `expires_at = now + lease_ttl` (default 24 h, configurable in `srvauthn.conf`). | `common/db.py`, `server/srvauthn.py`. | `SELECT expires_at FROM wg_peers` returns non-null for every active peer. |
| 4.2 | **Add a background sweeper in SrvAuthn.** A `threading.Thread` waking every 60 s, finds peers with `expires_at < now AND active=1`, runs `wg set <iface> peer <pub> remove`, sets `active=0`. | `server/leases.py` (new), `server/srvauthn.py`. | Set `lease_ttl_seconds = 60`, log in, wait 60 s — peer is gone from `wg show`. |
| 4.3 | **Final code hygiene pass.** Remove dead TLS/cert-pinning comments; ensure correct `from common.db import …` imports; ensure `__init__.py` at every package root. | several. | `python -m client.userauthn --help`, `python -m server.srvauthn --help`, `python -m idp.app` all run without import errors. |
| 4.4 | **Final spec-compliance walkthrough.** Open `ProjectSpec.pdf` next to the code and tick every item in the checklist in `RUNBOOK.md`. | none. | Every box ticked. |
| 4.5 | **Pre-submission packaging dry-run.** Move working-notes files (`AUDIT.md`, `DESIGN.md`, `JUSTIFICATIONS.md`, `PROJECT_UNDERSTANDING.md`, `STEPS.md`) into `internal/` so they don't ship. | repo layout. | `ls` at root shows the four mandated folders + `README.md` + infra files. |
| 4.6 | **TOTP secret encryption at rest.** Generate `IAA_MASTER_KEY` (32 random bytes, via env var). Add `_encrypt(plaintext) → ciphertext` and `_decrypt(ciphertext) → plaintext` in `common/db.py` using `AES-256-GCM`. Rename `totp_secrets.secret` → `totp_secret_enc` (BLOB). Pass all TOTP storage through the helpers. The fail-closed check from 1.12 must enforce `IAA_MASTER_KEY` is set. | `common/db.py`, `idp/helpdesk/app.py`, `idp/app.py`. | `SELECT totp_secret_enc FROM totp_secrets` returns random-looking bytes; TOTP login still works. |

---

## Notes

- **Don't skip the end-to-end test at the end of each phase.** It's tempting; resist. Procedures are in `RUNBOOK.md`.
- **Commit per logical step**, not per phase. If a step fails, the previous commit is a known-working rollback point. Aim for ~25–35 commits across all four phases.
- **`DESIGN.md` is allowed to drift.** When you discover that a decision doesn't survive contact with the implementation, edit `DESIGN.md` *and* add an entry in `JUSTIFICATIONS.md` explaining what you chose instead and why.
- **Defer the report.** Notes go into `JUSTIFICATIONS.md` as you make decisions. The final `README.md` is written at the very end, fed by `DESIGN.md` + `AUDIT.md` + `JUSTIFICATIONS.md`.
- **Bonus features:** revisit `DESIGN.md` §9 after Phase 4 to pick 1–2 low-cost wins.

---

*This document is a working note — move it to `internal/` along with the other planning files before submission.*

# Audit — current codebase vs `ProjectSpec.pdf`

> Strict, line-by-line compliance check of every directive in *Project —
> WireGuard VPN user authentication* (André Zúquete, 2026-02-13) against
> the code that actually exists in this repository.
>
> Verdict legend: **✓** fully met · **±** met but with a deliberate
> implementation choice worth flagging · **✗** missing / partial · **+**
> beyond-spec hardening (potential bonus material).

---

## 1. Bottom line

The codebase satisfies every **mandatory** directive of the project
specification. The only requirement-level gaps are:

1. **One RBA example signal is not implemented.** The spec lists
   *"same/different Autonomous Service"* as one of the indicators to
   *"consider using"* for RBA (§3). The spec's language frames the list
   as illustrative (it ends with "etc."), and the project does implement
   the other three indicators it names. This is documented in
   `README.md` §13.

2. **`README.md` author block is unfilled.** The spec (§5) mandates the
   README identify *"the authors (number and name) and their percentual
   contribution to the overall project work"*. The file exists with a
   placeholder table; the three rows must be filled in before
   submission.

There are no places where the implementation **violates** a spec
directive — i.e. no clause whose text says one thing and the code does
the opposite.

The rest of this document is the detailed evidence.

---

## 2. Walk-through

### 2.1 §1 — Introduction

> *"This project focuses on designing and implementing a secure user
> authentication protocol for WireGuard VPN."*

Informational. No requirement.

### 2.2 §2 — WireGuard VPN

> *"Peers authenticate themselves with uncertified asymmetric key pairs,
> which are used to (frequently) setup the tunnel session key with a fast
> protocol called NoiseIK, which is a variant of the multipurpose
> two-message Noise protocol."*

Informational. Notable because the auth tunnel between UserAuthn and
SrvAuthn also uses Noise-IK (see §2.3 of the spec walkthrough below) —
the same handshake pattern WireGuard itself uses for its data plane.
Same key, same handshake, two planes.

> *Lists of 6 mandatory parameters per side.*

These are the parameters every WG peer needs. They appear as
requirements only insofar as the project must produce all of them. See
§2.3 below for the assignment.

### 2.3 §3 — Project Objectives

#### UserAuthn parameters

> *"The UserAuthn application will have 2 parameters:
> • WireGuard interface; • A username; • base configuration about the
> server/gateway."*

The spec says "2 parameters" but lists three bullets — taken as the
three bullets being the actual list.

`client/userauthn.py:main` argparse:

```python
parser.add_argument("--interface", required=True, ...)
parser.add_argument("--username",  required=True, ...)
parser.add_argument("--config",    required=True, ...)
parser.add_argument("--port",      type=int, ...)            # optional override
parser.add_argument("--proxy-port", type=int, default=18080) # optional proxy port
```

Verdict: **✓**

#### UserAuthn base configuration content

> *"The base configuration will have a partial definition of a WireGuard
> peer (the server/gateway): public key (3), public IP address (4); and
> UDP port (5)."*

`client/base.conf.example`:

```ini
[server]
public_key  = REPLACE_WITH_SERVER_PUBKEY      # param 3
address     = YOUR_SERVER_IP                  # param 4
port        = 51820                           # param 5
auth_port   = 9999                            # tunnel port (optional)
```

Verdict: **✓**

#### Client WG parameter generation responsibilities

> *"The other 3 parameters required to configure a WireGuard client (1, 2
> and 6) must be either generated locally on each execution (6) or
> provided by the SrvAuthn application (1 and 2)."*

Strict reading: PSK (param 6) must be locally generated; secret key
(1) and private IP (2) must be server-provided. The implementation
follows this exactly:

| Param | Where it comes from | Code |
|---    |---                  |---   |
| 1 — client secret key   | server-generated post-auth                  | `server/srvauthn.py:wg_keypair` (calls `wg genkey \| wg pubkey`). Private half ships down the tunnel as `client_wg_private_key`. |
| 2 — client private IP   | server-allocated atomically post-auth       | `common/db.py:lease_next_ip` (inside `BEGIN IMMEDIATE`). Returned as `client_ip`. |
| 6 — pre-shared key      | client-generated before opening the tunnel  | `client/userauthn.py:generate_psk` (calls `wg genpsk`). Sent in the hello. Server echoes it back; client refuses to apply if it changes. |

Verdict: **✓**

#### SrvAuthn parameters

> *"The SrvAuthn application will have 2 parameters:
> • WireGuard interface; • base configuration file about itself
> (parameters 1, 2 and 3)."*

`server/srvauthn.py:main` argparse:

```python
parser.add_argument("--interface", default="wg0", ...)
parser.add_argument("--config",    default="srvauthn.conf", ...)
parser.add_argument("--port",      type=int, default=9999, ...) # optional override
```

The base config (`server/srvauthn.conf.example`) carries the three WG
"about itself" parameters:

| Param | Where it lives | Notes |
|---    |---             |---    |
| 1 — secret key       | `wg_private_key_file = /etc/wireguard/privatekey-server`              | indirected through a file path; the actual 32 random bytes live in that file |
| 2 — private IP       | `internal_subnet = 10.10.10.0/24` (the server reserves `.1`)          | strict-text reading: the spec asks for *"The (private) IP address"* (singular) of the tunnel endpoint. We declare the subnet and reserve `.1` for the server; the server's own IP is `10.10.10.1`, set by `wireguard/wg0.conf` (built by `scripts/init-wg.sh`). Functionally equivalent. |
| 3 — UDP port         | `wg_listen_port = 51820`                                              | literal |

Verdict: **±** — strictly compliant in substance, with the minor
implementation choice that the server's own IP is `10.10.10.1` by
convention (set in `wg0.conf`) rather than a separate field in
`srvauthn.conf`. No clause in the spec is violated.

#### Per-host server-side WG parameters

> *"All user host's configurations will be built upon a proper user
> authentication (parameters 4, 5 and 6 per host)."*

For every authenticated user the server-side gets params 4 (user
pubkey), 5 (user private IP), and 6 (PSK). All three are produced by
the provisioning path:

- `common/db.py:lease_next_ip` writes a new `wg_peers` row with
  `client_pubkey`, `client_ip`, `psk`.
- `server/srvauthn.py:register_wg_peer` then runs
  `wg set <iface> peer <client_pubkey> preshared-key <file> allowed-ips <client_ip>/32 persistent-keepalive 25`.
- The same `[Peer]` block is appended to `/etc/wireguard/<iface>.conf`
  so a `wg-quick down/up` cycle preserves the lease.

Verdict: **✓**

#### Transport port between UserAuthn and SrvAuthn

> *"You can used a fixed transport port for implementing the dialog
> between the UserAuthn and SrvAuthn application. Or you can provide its
> configuration with an extra, optional parameter in both applications."*

Default TCP 9999, override on both sides via `--port`.

Verdict: **✓**

#### MFA — three mandatory technologies

> *"For MFA you must deploy 3 mandatory technologies: password-based
> (challenge-response-based), TOTP and FIDO2."*

| Factor | Code | Notes |
|---    |---   |---    |
| Password (challenge-response) | `idp/app.py:mfa_password_challenge` + `:mfa_password`, `idp/static/js/scrypt.js` + `password_cr.js`, `common/db.py:consume_password_nonce` | scrypt verifier + HMAC over a single-use nonce. The raw password never leaves the browser. |
| TOTP                          | `idp/app.py:mfa_totp` (pyotp, valid_window=1)                                | RFC 6238. Enrolment in `idp/helpdesk/app.py:reset_totp` + `confirm_totp`. |
| FIDO2                         | `idp/app.py:mfa_fido2_start` + `:mfa_fido2_finish`                          | `user_verification=REQUIRED` on both ends. |

Verdict: **✓**

#### MFA ordering

> *"Consider the first the less robust (but probably more convenient) and
> the last the most robust (by also the less robust to loss, theft or
> malfunction)."*

The PAM module emits factors in `[password, totp, fido2]` order
(`pam_vpnmfa.c:required_factors`). Tier mapping:

```
L1 (score <  30)  →  password                     (least robust)
L2 (score <  60)  →  password + TOTP
L3 (score >= 60)  →  password + TOTP + FIDO2      (most robust)
```

Verdict: **✓**

#### IdP technology

> *"For the user authentication you will have to use an IdP, either
> through SAML or OAuth 2.0."*

OAuth 2.0 — specifically RFC 8628 (Device Authorization Grant), as
suggested by §4. Implemented in `idp/app.py`.

Verdict: **✓**

#### IdP implements MFA + RBA, SrvAuthn trusts IdP

> *"This IdP is the component that implements MFA and RBA, and the
> SrvAuthn application trusts on its behavior."*

SrvAuthn calls `POST /oauth/device/code`, polls `POST /oauth/token`,
then calls `GET /oauth/userinfo` with the bearer token. It does not
re-verify anything the IdP returns. The MFA + RBA logic is entirely
inside the IdP (`idp/rba.py`, `idp/pam_bridge.py`,
`idp/pam_iaa/src/pam_vpnmfa.c`, `idp/app.py`).

Verdict: **✓**

#### RBA indicators

> *"For RBA consider using the following key indicators for taking a more
> demanding authentication: IP address of the user host (same/different,
> same/different Autonomous Service), authentication failures, ordinary
> time of the day for VPN creation, etc."*

The verb is *"consider using"* and the list ends with *"etc."* —
illustrative, not exhaustive. The implementation covers three of the
four explicitly named indicators:

| Indicator                                | Implemented? | Code                            |
|---                                       |---           |---                              |
| IP same/different                        | ✓            | `idp/rba.py` — `rba_ip_history` membership; first-ever-login bonus |
| Same/different Autonomous Service        | ✗            | not implemented                 |
| Authentication failures                  | ✓            | `idp/rba.py` — `get_recent_failures(username, minutes=30)` |
| Ordinary time of day                     | ✓            | `idp/rba.py:_is_unusual_hour` — 00:00–06:00 UTC penalty |

Verdict: **±** — three of four named indicators implemented;
"Autonomous Service" not. The spec's list is illustrative
(*"consider using ... etc."*) so this is a soft deviation, but it is
the one place where named text in the spec is not reflected in the
code. Documented in `README.md` §13.

### 2.4 §4 — Implementation details

#### Browser-based MFA

> *"The user authentication is easier to implement with a browser, because
> it simplifies the MFA deployment."*

Hint, not requirement. We do use a browser — the user opens the
verification URI, completes MFA in HTML forms, and the FIDO2 flow rides
on WebAuthn (`idp/static/js/webauthn.js`).

Verdict: **✓** (hint followed)

#### Trust anchor

> *"The project must use the clients' knowledge of the servers/gateways's
> WireGuard public key as a source of trust."*

The client passes the WG public key (from `base.conf:public_key`) to
`tunnel.connect`, which calls `NoiseHandshake.initiator(server_static_pub=...)`.
The Noise-IK handshake fails (AEAD tag mismatch on the responder's
payload) if the server cannot prove possession of the matching private
key. The server's private key is loaded at startup from
`/etc/wireguard/privatekey-server`
(`server/srvauthn.py:_load_server_wg_private_key`) — the same file
`wg-quick up wg0` uses for the data plane. One key, two planes.

No certificates, no CA, no PKI.

Verdict: **✓**

#### Tunnel for browser ↔ IdP

> *"One interesting possibility is to explore HTTP interactions through a
> secure tunnel (e.g. via TLS) created between the UserAuthn and the
> SrvAuthn application. In this case, the user browser can use HTTP
> (instead of HTTPS), connects to a TCP port deployed by UserAuthn (client
> tunnel endpoint), and the SrvAuthn redirects the traffic from the tunnel
> to the IdP. This eliminates the user side need to authenticate the IdP;
> all that is necessary is to authenticate the SrvAuthn application with
> the WireGuard's public key (something similar is provided by SSH
> tunnels)."*

The "(e.g. via TLS)" is given as an example of *a* secure tunnel; the
actual requirement is *some* secure tunnel that authenticates SrvAuthn
via the WG public key. Noise-IK satisfies this directly (because the
responder's static key *is* the WG public key the client already
trusts).

`client/proxy.py:ProxyServer` listens on `127.0.0.1:18080`. For every
browser connection it opens a Noise-IK tunnel to SrvAuthn and sends
`{"service":"proxy"}` as the first encrypted frame.
`server/proxy.py:handle_proxy` then opens a TCP connection to the IdP
at `localhost:8080` and pumps bytes both ways. The IdP's `ORIGIN` is
`http://127.0.0.1:18080`, so the `verification_uri_complete` it
generates points at the proxy port — the browser opens that, traffic
flows over Noise, the user never sees the gateway address.

Verdict: **✓** (Noise-IK chosen as the secure tunnel; spec wording
allows "e.g. via TLS" as an example, not a requirement)

#### OAuth Device Authorization Grant

> *"For exploring OAuth 2.0, it may be interesting to select the Device
> Authorization Grant flow, since it simplifies the integration of the
> UserAuthn application with a browser."*

Implemented in full (RFC 8628):

- `POST /oauth/device/code` — `idp/app.py:device_code`.
- `GET /oauth/device` + `POST /oauth/device/verify` — user submission.
- `POST /oauth/token` — SrvAuthn polling; returns
  `authorization_pending` / `access_denied` / `expired_token` / success.
- `GET /oauth/userinfo` — bearer-token userinfo.

Verdict: **✓**

#### MFA + RBA orchestrated by PAM

> *"The IdP MFA and RBA orchestration must be done with PAM. You must
> implement a PAM module, to be launched from the IdP PAM profile
> configuration, that provides instructions to the IdP about the
> authentication methods to be used and their sequence."*

Every clause is satisfied:

| Clause | Code |
|---|---|
| "MFA and RBA orchestration must be done with PAM" | `idp/pam_bridge.py` calls `pam_authenticate("iaa-vpn", username)` via the ctypes wrapper in `common/libpam.py` |
| "implement a PAM module" | `idp/pam_iaa/src/pam_vpnmfa.c` — compiled into `/usr/lib/x86_64-linux-gnu/security/pam_vpnmfa.so` at image build time |
| "launched from the IdP PAM profile configuration" | `idp/pam_iaa/pam.d/iaa-vpn` — `auth required pam_vpnmfa.so`; installed to `/etc/pam.d/iaa-vpn` |
| "provides instructions about the authentication methods to be used and their sequence" | `pam_sm_authenticate` reads `pam_getenv("IAA_RISK_SCORE")`, maps to tier, emits `FACTOR:<name>` conv messages in `[password, totp, fido2]` order |

Verdict: **✓**

#### PAM callback contract

> *"You can use the PAM callback function to give instructions to the IdP
> and for collecting authentication results (success / failure / no
> availability)."*

The conv contract:

| Style                 | Message payload                    | Expected response                |
|---                    |---                                 |---                               |
| `PAM_PROMPT_ECHO_OFF` | `FACTOR:password`/`totp`/`fido2`   | `OK` / `FAIL` / `UNAVAILABLE`    |
| `PAM_TEXT_INFO`       | `INFO:tier=L2 score=30` etc.       | (any string)                     |

`OK` → continue to next factor; `FAIL` → return `PAM_AUTH_ERR`;
`UNAVAILABLE` → return `PAM_AUTHINFO_UNAVAIL`. The bridge enforces the
three-string vocabulary in
`idp/pam_bridge.py:submit_factor_result`.

Verdict: **✓**

#### Enrolment and credential-update interface

> *"As in any IdP, an enrolment process must exist, as well as a
> credential update possibility. Provide an interface for it, but without
> any security-related validations. Assume that that interface is
> internal and exclusive for an helpdesk service."*

The helpdesk (`idp/helpdesk/app.py`) provides:

- create user (`POST /user/create`),
- set / reset password (`POST /user/<u>/password`) — overwrites the
  scrypt verifier,
- generate / reset TOTP (`POST /user/<u>/totp`), confirm
  (`POST /user/<u>/totp/confirm`), QR (`GET /user/<u>/totp/qr`),
- register FIDO2 (`POST /user/<u>/fido2/start` + `/finish`), delete
  (`POST /user/<u>/fido2/<cred_id>/delete`).

No login is required — *"without any security-related validations"*.
Confidentiality is enforced topologically: the helpdesk binds
`127.0.0.1` and runs in `network_mode: host`, so the bind is literally
the host's loopback. The helpdesk is unreachable from off-host.

Verdict: **✓**

### 2.5 §5 — Project execution, delivery and grading

#### Folder structure

> *"Delivery should consist of a ZIP file with at least 4 folders and a
> file: client, server, idp, common, README.md"*

| Path | Present | Contents (summary) |
|---|---|---|
| `client/`   | ✓ | `userauthn.py`, `tunnel.py`, `proxy.py`, `base.conf.example` |
| `server/`   | ✓ | `srvauthn.py`, `tunnel.py`, `proxy.py`, `leases.py`, `entrypoint.sh`, `Dockerfile`, `srvauthn.conf.example` |
| `idp/`      | ✓ | `app.py`, `pam_bridge.py`, `rba.py`, `helpdesk/`, `pam_iaa/`, `templates/`, `static/`, `Dockerfile` |
| `common/`   | ✓ | `db.py`, `config.py`, `libpam.py`, `framing.py`, `noise.py` |
| `README.md` | ✓ | — |

Verdict: **✓**

#### README content requirements

> *"README.md: contains a succinct report of the project design and
> implementation, which includes a justified description of all
> implemented features. It must clearly identify the authors (number and
> name), their percentual contribution to the overall project work and
> the features not implemented at all or partially implemented."*

| Sub-requirement | Status |
|---|---|
| Succinct project design + implementation report | ✓ (sections 1–11) |
| Justifications for each implemented feature | ✓ (interleaved throughout sections 4–10) |
| Authors — number and name | **✗** placeholder table waiting for fill-in (§12) |
| Per-author contribution percentages | **✗** same placeholder |
| Features not implemented or partially implemented | ✓ (§13 — Autonomous-Service RBA signal) |

Verdict: **±** — content is complete, authors block needs filling in
before submission.

#### Plagiarism / external code

> *"The use of existing code snippets, applications, or any other external
> functional element without proper acknowledgement is strictly
> forbidden."*

`README.md §14` lists every external library used (flask, pyotp,
webauthn, cryptography, qrcode + pillow) and what they are used for, and
explicitly identifies as original work: the Noise-IK implementation, the
browser-side scrypt, the PAM C module, and the libpam ctypes wrapper.

Verdict: **✓**

#### Grading split

> *"Projects will be graded according to: The suitability/correctness of
> the options taken (70%); The documentation produced (30%). A maximum of
> 10% bonus will be granted to projects that implement some interesting,
> non-mandatory features."*

Informational. The candidate bonus features are listed in §4 below.

### 2.6 §6 — References

Two reading references (WireGuard Quick Start, Linux-PAM Module Writers'
Guide). No requirement.

---

## 3. Compliance matrix (condensed)

| # | Spec clause                                                                       | Status | Evidence |
|---|---|---|---|
|  1 | UserAuthn takes WG interface + username + base config                              | ✓ | `client/userauthn.py:main` argparse |
|  2 | UserAuthn base config carries server params 3, 4, 5                                | ✓ | `client/base.conf.example` |
|  3 | Client WG params 1 + 2 server-provided; param 6 locally generated                  | ✓ | `server/srvauthn.py:wg_keypair`, `common/db.py:lease_next_ip`, `client/userauthn.py:generate_psk` |
|  4 | SrvAuthn takes WG interface + base config (params 1, 2, 3)                          | ± | `server/srvauthn.py:main`; server private IP is by convention `.1` of `internal_subnet` (in `wg0.conf`) rather than an explicit `srvauthn.conf` field |
|  5 | Per-user server-side WG params 4, 5, 6 built upon authentication                    | ✓ | `wg_peers` table + `register_wg_peer` |
|  6 | Fixed transport port with optional override                                         | ✓ | default 9999, `--port` override on both sides |
|  7 | MFA — password (challenge-response)                                                  | ✓ | scrypt verifier + HMAC nonce proof (see §2.3) |
|  8 | MFA — TOTP                                                                          | ✓ | `idp/app.py:mfa_totp` |
|  9 | MFA — FIDO2                                                                         | ✓ | `idp/app.py:mfa_fido2_*` with `UV=REQUIRED` |
| 10 | Factor robustness ordering                                                          | ✓ | tier mapping in `pam_vpnmfa.c` |
| 11 | IdP via OAuth 2.0 (or SAML)                                                          | ✓ | OAuth 2.0 Device Grant |
| 12 | IdP implements MFA + RBA; SrvAuthn trusts IdP                                       | ✓ | architecture |
| 13 | RBA — IP indicator                                                                  | ✓ | `idp/rba.py` |
| 14 | RBA — "Autonomous Service" indicator                                                | ✗ | **not implemented**; declared in `README.md §13` |
| 15 | RBA — auth-failures indicator                                                       | ✓ | `idp/rba.py` |
| 16 | RBA — time-of-day indicator                                                         | ✓ | `idp/rba.py` |
| 17 | Browser-based MFA flow                                                              | ✓ | `webbrowser.open(verification_uri)` |
| 18 | WG public key as source of trust                                                    | ✓ | Noise-IK responder static = WG public key |
| 19 | Secure tunnel between UserAuthn and SrvAuthn                                        | ✓ | Noise-IK; spec example was "e.g. via TLS" |
| 20 | Browser connects to a UserAuthn TCP port over HTTP; SrvAuthn forwards to IdP        | ✓ | `client/proxy.py` ↔ `server/proxy.py` |
| 21 | OAuth Device Authorization Grant                                                    | ✓ | RFC 8628 implemented |
| 22 | MFA + RBA orchestration done with PAM                                               | ✓ | `idp/pam_bridge.py` calls `pam_authenticate` |
| 23 | Custom PAM module launched from IdP PAM profile                                     | ✓ | `pam_vpnmfa.so` + `/etc/pam.d/iaa-vpn` |
| 24 | PAM module provides instructions about methods and their sequence                    | ✓ | `pam_sm_authenticate` emits ordered `FACTOR:<name>` conv messages |
| 25 | PAM callback collects results: success / failure / no availability                  | ✓ | `OK` / `FAIL` / `UNAVAILABLE` vocabulary |
| 26 | Enrolment + credential-update interface (internal helpdesk, no security checks)      | ✓ | `idp/helpdesk/app.py`, loopback-only |
| 27 | ZIP contains `client/`, `server/`, `idp/`, `common/`, `README.md`                    | ✓ (folders) + ± (README has placeholder authors) | layout |
| 28 | README — design + implementation + justifications                                   | ✓ | `README.md §1–§11` |
| 29 | README — authors (number + name)                                                    | ✗ | placeholder table in `README.md §12` |
| 30 | README — percentual contribution per author                                         | ✗ | placeholder table in `README.md §12` |
| 31 | README — features not implemented                                                   | ✓ | `README.md §13` |
| 32 | External code acknowledged                                                          | ✓ | `README.md §14` |

---

## 4. Beyond-spec hardening (bonus candidates)

The spec allows up to 10 % bonus for "interesting, non-mandatory
features". The codebase has the following beyond what the spec requires:

| # | Feature                                                                                  | Code |
|---|---|---|
| B1 | OAuth access tokens hashed at rest (`SHA-256`) with 60 s TTL **and single-use** (`used_at`) | `common/db.py:create_access_token` + `mark_token_used`; `idp/app.py:token` + `userinfo` |
| B2 | Account lockout (5 failures / 5 min → 15 min lock), checked at every `mfa_*` route entry | `common/db.py:record_factor_failure` + `is_user_locked` + `lockout_seconds_remaining`; `idp/app.py:_lockout_response` |
| B3 | TOTP shared secrets encrypted at rest with **AES-256-GCM**; master key validated at startup | `common/db.py:_encrypt` + `_decrypt` + `_aesgcm`; `common/config.py:require_master_key` |
| B4 | Fail-closed startup — apps refuse to launch with missing or placeholder secrets             | `common/config.py:require_env` |
| B5 | Race-safe IP allocation via `BEGIN IMMEDIATE`                                                | `common/db.py:lease_next_ip` |
| B6 | Replay-safe password challenge — single-use nonce atomically consumed                       | `common/db.py:consume_password_nonce` |
| B7 | Lease expiry — every WG peer has `expires_at`; background sweeper removes expired peers     | `wg_peers.expires_at`, `server/leases.py` |
| B8 | FIDO2 `user_verification = REQUIRED` (not the library default `PREFERRED`)                  | `idp/helpdesk/app.py:fido2_register_start`; `idp/app.py:mfa_fido2_start`/`_finish` |
| B9 | WG key shape validation before any `wg set`                                                 | `server/srvauthn.py:is_valid_wg_key` |
| B10 | One-command setup + automated VM E2E test + tiered teardown                                | `scripts/setup.py`, `scripts/test_e2e.py`, `scripts/teardown.py` |

None of these are required by the spec.

---

## 5. "Does the implementation go *against* the spec anywhere?"

Reading the spec strictly, looking for clauses where the implementation
does the *opposite* of what is required:

| Clause | Implementation | Goes against? |
|---|---|---|
| "must use the clients' knowledge of the servers/gateways's WireGuard public key as a source of trust" | Noise-IK responder static = WG public key | **No** |
| Client params 1, 2 must be server-provided; 6 must be locally generated | Implemented exactly that way | **No** |
| "must deploy 3 mandatory technologies: password-based (challenge-response-based), TOTP and FIDO2" | All three are present | **No** |
| Password is "challenge-response-based" | scrypt verifier + HMAC over single-use nonce; raw password never sent | **No** |
| "must be done with PAM" (MFA + RBA orchestration) | `pam_authenticate("iaa-vpn", …)` is the orchestrator; sequencing lives inside `pam_vpnmfa.c` | **No** |
| "implement a PAM module, launched from the IdP PAM profile" | `pam_vpnmfa.so` loaded by `/etc/pam.d/iaa-vpn` | **No** |
| "provide an interface for [enrolment + credential update], but without any security-related validations" | Helpdesk has no authentication of its own; is bound loopback-only | **No** |
| Folders `client/`, `server/`, `idp/`, `common/` | All present at root | **No** |
| `README.md` at root | Present | **No** |
| External code must be acknowledged | `README.md §14` lists every dependency | **No** |

**There is no place where the implementation goes against the spec.**
The two gaps (Autonomous-Service RBA signal, blank authors block) are
omissions, not contradictions.

---

## 6. Action items before submission

In strict priority order:

1. **Fill in `README.md §12`** with author numbers + names + per-author
   contribution percentages.
2. **Do a clean rebuild** to prove reproducibility:

   ```bash
   python3 scripts/teardown.py --reset -y
   python3 scripts/setup.py
   python3 scripts/test_e2e.py
   ```

   Expect `ALL CHECKS PASSED — stack verified end-to-end!` at the end.
3. **Package** with `git archive --format=zip --output=submission.zip HEAD`
   and verify the archive contains exactly `client/`, `server/`, `idp/`,
   `common/`, `README.md`, plus the other top-level helper files
   (`docker-compose.yml`, `RUN.md`, `AUDIT.md`, `scripts/`).

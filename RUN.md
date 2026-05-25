# Running the stack — quick guide for colleagues

> Everything below assumes you cloned the repo and are sitting at its root.
> For the design / architecture story see `PROJECT_UNDERSTANDING.md`;
> for spec-vs-implementation see `AUDIT.md`.

---

## TL;DR

```bash
python3 scripts/setup.py        # one-time, idempotent
python3 scripts/test_e2e.py     # full VPN bring-up + ping inside a Multipass VM
```

The first command builds three Docker containers, generates fresh secrets,
brings `wg0` up on your host, and enrols a test user `alice / TestPass123`.
The second command launches a Multipass VM, opens a Noise-IK tunnel back to
your host, completes the OAuth Device Grant programmatically, brings up
`wg0` inside the VM, and pings the gateway. You should see `ALL CHECKS
PASSED — stack verified end-to-end!`.

To stop everything later: `python3 scripts/teardown.py` (just stop) or
`python3 scripts/teardown.py --reset -y` (stop + wipe generated files +
docker images).

---

## Prerequisites (Linux host)

```bash
sudo apt install docker.io docker-compose-v2 wireguard-tools
```

Plus Multipass for the VM-based E2E test (Ubuntu cloud VM):

```bash
sudo snap install multipass
```

Add yourself to the `docker` group so the scripts don't need `sudo`:

```bash
sudo usermod -aG docker $USER && newgrp docker
```

Verify the kernel WireGuard module is available:

```bash
sudo modprobe wireguard && lsmod | grep wireguard
```

You should not need to install Python dependencies on the host — everything
Python runs inside containers (and a Multipass VM for the E2E test).

---

## What `setup.py` does

Seven idempotent steps. Re-running it is safe; it only re-creates things
that don't already exist (use `--force` to overwrite).

1. Checks `docker` + `wg` are present and that the Docker daemon is reachable.
2. Generates `.env` with fresh random `SECRET_KEY`, `OAUTH_CLIENT_SECRET`,
   and `IAA_MASTER_KEY`. Pre-populates `RP_ID=127.0.0.1`,
   `ORIGIN=http://127.0.0.1:18080`, `HELPDESK_ORIGIN=http://127.0.0.1:8081`.
3. Generates the server's WireGuard keypair into
   `wireguard/{privatekey-server, publickey-server, wg0.conf}` and patches
   the public key into `.env`.
4. Generates `server/srvauthn.conf` from the example template.
5. `docker compose up -d --build` — builds and starts `vpn-idp`,
   `vpn-helpdesk`, `vpn-srvauthn`. Waits for each to log "ready".
6. Enrols `alice` via the helpdesk: creates user, sets password
   `TestPass123`, generates and confirms a TOTP secret.

When it finishes:

| Service       | Where it listens                        |
|---            |---                                      |
| IdP           | `http://localhost:8080`                  |
| Helpdesk      | `http://localhost:8081` (host loopback) |
| SrvAuthn      | TCP `:9999` (Noise-IK)                   |
| WireGuard     | UDP `:51820`, server IP `10.10.10.1/24`  |

---

## What `test_e2e.py` does

The "everything works" test. Eight steps:

0. Resets state from previous runs (live WG peers, DB auth tables, unlocks any
   locked-out users).
1. Ensures the Multipass VM `vpn-client` exists and is running (launches
   Ubuntu 24.04 on first run — takes 1–3 minutes).
2. Discovers the gateway IP from the VM's perspective (`ip route show default`).
3. Mounts the repo into the VM and installs `wireguard-tools`,
   `python3`, `python3-cryptography`.
4. Writes `client/base.conf` with the gateway IP, server public key, etc.
5. Fetches alice's TOTP seed from the DB (decrypts it via `common.db`).
6. Launches `userauthn.py` inside the VM and, in parallel, completes the
   OAuth flow programmatically — GET the password challenge, derive
   scrypt + HMAC proof in Python, POST it, then POST the current TOTP code.
7. Verifies `wg show wg0` on both sides, then `ping -c 3 10.10.10.1` from
   the VM. Expects 0 % packet loss.
8. Smoke-tests the local HTTP proxy on `127.0.0.1:18080`.

Total runtime: ~10–20 s on a warm cache, ~3 min on the very first run when
Multipass has to download Ubuntu.

---

## Teardown

```bash
# Just stop the containers (DB, keys, configs preserved):
python3 scripts/teardown.py

# Full reset — wipe .env, srvauthn.conf, base.conf, WG keys, SQLite DB,
# and local Docker images. Next setup.py is a clean install.
python3 scripts/teardown.py --reset -y

# Also delete the Multipass VM:
python3 scripts/teardown.py --reset --vm -y
```

---

## Manual demo via a real browser

If you want to walk through the flow by hand instead of running the
automated test:

```bash
# 1. Make sure the stack is up.
python3 scripts/setup.py

# 2. From inside the VM (or any client machine where the gateway is reachable):
sudo python3 client/userauthn.py \
    --interface wg0 \
    --username  alice \
    --config    client/base.conf
```

`userauthn.py` prints a `Your code:` line and opens a browser pointed at the
local proxy. Type your password and TOTP code; the VPN comes up when both
factors verify.

---

## Docker client fallback

For quick testing without a VM, you can run the client in Docker on the host. The flow is the same as above, but instead of `python3 client/userauthn.py` use the optional client profile:

```bash
docker compose --profile client up -d --build client
docker compose exec client bash
```

Inside the `vpn-client` shell, create a Docker-specific base config:

```bash
cat > /tmp/base.conf <<EOF
[server]
public_key  = ${SERVER_PUBKEY}
address     = host.docker.internal
port        = 51820
auth_port   = 9999
allowed_ips = 10.10.10.0/24
EOF
```

Then run the client:

```bash
python3 -u client/userauthn.py \
  --interface wg0 \
  --username alice \
  --config /tmp/base.conf \
  --proxy-host 0.0.0.0
```

Open the printed URL from the host browser. The browser reaches
`127.0.0.1:18080`, Docker forwards it into the client container, and the
client proxy carries the HTTP flow through the authenticated Noise tunnel.

---

## Common pitfalls

- **"docker compose up failed"** — almost always either (a) port 8080 is
  already in use, or (b) the user isn't in the `docker` group. `ss -ltnp |
  grep :8080` and `id | grep docker` will tell you which.
- **"wg0 already exists"** — left over from a previous run. `sudo wg-quick
  down wg0` once, then re-run `setup.py`.
- **`scripts/test_e2e.py` hangs at the OAuth step** — the IdP's
  `IAA_MASTER_KEY` likely doesn't match the one TOTP was encrypted with
  (you regenerated `.env` without resetting the DB). Fix: `python3
  scripts/teardown.py --reset -y && python3 scripts/setup.py`.
- **WebAuthn / FIDO2 fails in a real browser** — `RP_ID` must be a suffix
  of the page origin. Both `127.0.0.1:18080` (login) and `127.0.0.1:8081`
  (helpdesk) need `RP_ID=127.0.0.1` in `.env`. `setup.py` does this for
  you; only relevant if you edit `.env` by hand.

---

## What `.env` looks like after `setup.py`

For reference — you should never need to edit this file by hand.

```ini
SERVER_PUBKEY=<32-byte base64 — the gateway's WG public key>
SECRET_KEY=<64 hex chars — Flask session key>
OAUTH_CLIENT_SECRET=<64 hex chars — SrvAuthn ↔ IdP shared secret>
IAA_MASTER_KEY=<32-byte base64 — AES-256-GCM key for TOTP at rest>
RP_ID=localhost
ORIGIN=http://localhost:18080
HELPDESK_ORIGIN=http://localhost:8081
```

All values are random per machine. Never commit `.env` (it's gitignored).

# ByteENDE

**Version 1.0.0** · **License: MIT** · **Author: [AliXByte](https://github.com/AliXByte)**

A multi-protocol encode/decode toolbox with two interfaces built on one shared core: a dashboard to use by hand, and a REST API for everything else.

- **Web panel** — a navy/cyan dashboard (matching the AliXByte brand mark) to run every tool by hand, plus API-key management and a full Customize page.
- **REST API** — secured with per-key Bearer tokens, scopes and per-key rate limiting.

Cross-platform by design: pure-stdlib core logic, `os.path`-only file handling, and dedicated launchers for Linux/macOS (`run.sh`) and Windows (`run.bat`).

## Table of contents

1. [Tools included](#tools-included)
2. [Project structure](#project-structure)
3. [Setup](#setup)
4. [Customize](#customize)
5. [Network & access control](#network--access-control)
6. [Configuration](#configuration-environment-variables)
7. [REST API](#rest-api)
8. [Security](#security)
9. [License](#license)

## Tools included

- Encode/Decode: Base64, Base32, Hex, Binary, URL, ROT13, Morse
- Hash: MD5, SHA1, SHA256, SHA512
- JWT: decode, encode (HS256/384/512), verify
- AES-256-GCM encrypt/decrypt (password-based, authenticated encryption)
- QR code: generate and read

## Project structure

```
ByteENDE/
├── core/                       # pure logic, no Flask dependency - reused by both the panel and the API
│   ├── codecs.py                 # Base64/32, Hex, Binary, URL, ROT13, Morse
│   ├── hashing.py                # MD5/SHA1/SHA256/SHA512
│   ├── jwt_tool.py               # decode / encode / verify
│   ├── crypto_aes.py             # AES-256-GCM, password-based (PBKDF2)
│   └── qr_tool.py                # generate / read (lazy-imported, optional deps)
├── web/
│   ├── app.py                    # Flask application factory: security headers, CSRF, cookies, network ACL hook
│   ├── auth.py                   # owner login (+ lockout), API-key storage, rate limiter, CSRF helpers
│   ├── network_acl.py            # IP/CIDR + MAC access rules, bind-address setting, audit log
│   ├── blueprints/
│   │   ├── auth_routes.py          # /setup /login /logout /account
│   │   ├── panel_routes.py         # dashboard, /keys/*, /settings, /network*, /panel/* (session-authenticated tool calls)
│   │   └── api_routes.py           # /api/v1/* public REST API (Bearer-token authenticated)
│   ├── templates/                 # Jinja2, extends base.html; _icons.html holds the shared SVG icon set
│   │   ├── settings.html            # "Customize" page: accent theme, density, effects, defaults, import/export
│   │   ├── network.html             # "Network" page: access rules, listen address, access log
│   │   └── blocked.html             # shown to a client denied by the network rules
│   └── static/
│       ├── style.css              # navy/cyan theme, accent variants, density & effect toggles
│       ├── app.js                 # tool wiring, Customize-page logic, toasts, confirm dialogs
│       ├── logo.png               # the AliXByte "AX" brand mark, used as-is
│       └── favicon.png            # rounded-corner derivative of logo.png, for the browser tab only
├── run.py                        # cross-platform entry point: `python run.py`
├── run.sh                        # Linux/macOS launcher (venv + deps + run)
├── run.bat                       # Windows launcher (venv + deps + run)
├── requirements.txt
├── LICENSE
└── data/                          # created at runtime: owner.json, keys.json, session.secret, network.json, access_log.jsonl (gitignored)
```

## Setup

### Linux / macOS
```bash
./run.sh
```

### Windows
```bat
run.bat
```

Either script creates a virtual environment, installs dependencies, and starts the app. You can also do it by hand on any OS:

```bash
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

QR *reading* also needs the system `zbar` library:
- Debian/Ubuntu: `sudo apt install libzbar0`
- macOS: `brew install zbar`
- Windows: the `pyzbar` wheel bundles it - no extra step.

Open `http://localhost:8800` — first visit creates the one owner account.

## Customize

The **Customize** page in the sidebar is a real settings panel, not decoration — every control applies instantly and is remembered per-browser (`localStorage`, nothing is sent to the server):

- **Accent color** — cyan (default, matches the AliXByte mark), violet, emerald, amber, rose.
- **Layout density** — comfortable or compact spacing.
- **Default Encode/Decode format** and **result-box font** (monospace or UI font).
- **Motion & effects** — independent toggles for the animated background and for transitions/pulse/glow effects, for a flatter or faster feel.
- **Behavior** — confirmation dialogs before deleting a key, toast notifications on copy.
- **Export / Import / Reset** — settings as a portable JSON file, to carry your setup to another browser or device.

## Network & access control

The **Network** page controls who can reach ByteENDE and keeps an audit trail of who did what. It's organized as four independent controls plus a log:

- **Dashboard access** — `Allow all` / `Allow only these` / `Block these`, with a list of IPs or CIDR ranges (e.g. `10.0.0.0/24`). Applies to the whole web panel.
- **API access** — the same three modes, applied separately to `/api/v1/*` only, since scripts and browsers usually come from different places. API keys still need their own scope and rate limit on top of this.
- **Device (MAC) access** — optional, off by default. Read the warning on the page before turning it on: a MAC address is only visible between devices on the *same local network*, so this only ever matches a device on your LAN (and only on Linux hosts, via the system ARP table). It can never see the MAC of a client connecting over the internet or through a router — use the IP rules above for remote access control.
- **Listen address** — `127.0.0.1` (this machine only, the default), `0.0.0.0` (every network interface), or a custom address. This is the same setting as `BYTEENDE_HOST` below; whichever was set more recently wins, and either way it only takes effect the next time ByteENDE starts, since a running process can't rebind its socket.
- **Access log** — every request ByteENDE has handled recently (IP, method, path, user, outcome), kept in `data/access_log.jsonl` and capped automatically so it can't grow without bound.

**Break-glass safety net:** the loopback address (`127.0.0.1`) always passes every rule, and the login screen plus the Network page itself are always reachable from any IP — both still fully gated behind your password. This means a misconfigured rule can restrict the rest of the dashboard or the API, but can never permanently lock the owner out of fixing it.

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `BYTEENDE_HOST` | `127.0.0.1` | Set to `0.0.0.0` to expose on the network (put a TLS reverse proxy in front if you do) |
| `BYTEENDE_PORT` | `8800` | Port to listen on |
| `BYTEENDE_FORCE_HTTPS` | unset | Set to `1` when served behind TLS, so the session cookie gets the `Secure` flag and HSTS is sent |

## REST API

Create a key from the panel's **API keys** page, then:

```bash
curl -X POST http://localhost:8800/api/v1/codec \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"codec":"base64","mode":"encode","text":"hello"}'
```

| Endpoint | Scope | Body |
|---|---|---|
| `POST /api/v1/codec` | `codec` | `{codec, mode, text}` |
| `POST /api/v1/hash` | `hash` | `{text, algo?}` |
| `POST /api/v1/jwt/decode` | `jwt` | `{token}` |
| `POST /api/v1/jwt/encode` | `jwt` | `{payload, secret, alg?}` |
| `POST /api/v1/jwt/verify` | `jwt` | `{token, secret}` |
| `POST /api/v1/aes/encrypt` | `aes` | `{text, password}` |
| `POST /api/v1/aes/decrypt` | `aes` | `{blob, password}` |
| `POST /api/v1/qr/generate` | `qr` | `{text}` → PNG |
| `POST /api/v1/qr/read` | `qr` | multipart `image` |
| `GET /api/v1/ping` | none | health check |

Each key has its own scopes and requests/minute limit, set when it's created. `/api/v1/*` never uses cookies or CSRF tokens — it's stateless Bearer-token auth only.

## Security

ByteENDE handles crypto keys and API tokens, so it is hardened well beyond the minimum. (This section documents the engineering for anyone auditing the project; the in-product login and setup screens deliberately keep this detail out of the UI.)

- **Password storage** — a salted, iterated key-derivation hash. Verification uses a constant-time comparison and pays the same computational cost even for an unknown username, so failed logins can't be timed to tell "wrong user" from "wrong password" apart.
- **Login lockout** — repeated failed attempts within a short window lock that username out temporarily, defeating online brute-force against the single owner account.
- **API tokens** — generated with a cryptographically secure random generator; only a one-way hash is ever persisted. The raw token is shown exactly once, at creation.
- **Per-key scopes & rate limits** — a key can only call the tool groups it was granted, and is capped at its own requests/minute (sliding 60s window), so one leaked integration key has bounded blast radius.
- **AES-256-GCM** — authenticated encryption (AEAD): tampered or wrong-password ciphertext fails to decrypt instead of silently returning garbage.
- **CSRF protection** — every session-cookie HTML form carries a per-session token checked with constant-time comparison before the request is processed. The REST API is exempt by design — it's Bearer-token authenticated and carries no cookie, so it isn't a CSRF target.
- **Secure cookies** — `HttpOnly` and `SameSite=Lax` always; `Secure` automatically when `BYTEENDE_FORCE_HTTPS=1` (behind a TLS proxy), plus HSTS in that mode.
- **HTTP security headers** on every response — `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`.
- **Request size cap** — 5 MB max body, enough for a QR image upload, tight enough to blunt naive resource-exhaustion attempts.
- **Safe-by-default bind** — binds to `127.0.0.1` unless you explicitly opt into `0.0.0.0`.
- **Secrets never committed** — `data/owner.json`, `data/keys.json`, `data/session.secret`, `data/network.json` and `data/access_log.jsonl` are all in `.gitignore`.
- **Network access control & audit log** — optional IP/CIDR and (LAN-only, best-effort) MAC filtering for the dashboard and the API separately, plus a log of which IP did what. See [Network & access control](#network--access-control).

The in-memory rate limiter and login-lockout tracker are per-process (fine for a single-worker deployment); run behind Redis or a shared store if you scale to multiple workers.

## License

Released under the [MIT License](LICENSE) — see `LICENSE` for the full text.

## Credits

ByteENDE is designed, built and maintained by **[AliXByte](https://github.com/AliXByte)**.

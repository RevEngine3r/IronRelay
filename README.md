# IronRelay

TCP-over-HTTP tunnel with zero dependencies on a VPS.

```
[Your App]
    │  TCP / SOCKS5
    ▼
[Go Client]  ──POST──▶  [Google Apps Script]  ──POST──▶  [Cloudflare Worker]
                              (stateless relay)               │  cloudflare:sockets
                                                         TCP dial to Internet
```

## Components

| Path | Language | Role |
|---|---|---|
| `client/` | Go | SOCKS5 listener + HTTP poll loop |
| `worker/worker.js` | JS (CF Workers) | Exit node, TCP via `cloudflare:sockets` |
| `relay/Code.gs` | Google Apps Script | Stateless HTTP forwarder |

## Frame Wire Format

```
Offset  Size  Field
──────────────────────────────────────────
0       1     cmd   SYN=1 DATA=2 FIN=3 ACK=4
1       16    session_id  (random bytes)
17      4     payload_len (big-endian uint32)
21      N     payload
```

- **SYN** payload = `"host:port"` string
- **DATA** payload = raw TCP bytes from client
- **FIN** payload = empty
- **ACK** payload = raw TCP bytes from remote server

Multiple frames are concatenated in one POST body (self-delimiting via headers).
No encryption at the frame layer — HTTPS covers the full path.

## Quick Start

### 1. Deploy CF Worker

```bash
cd worker
npm install -g wrangler
# edit wrangler.toml: set RELAY_TOKEN
wrangler deploy
```

### 2. Deploy GS Relay

1. Open [script.google.com](https://script.google.com), create new project
2. Paste `relay/Code.gs`
3. Set `CF_WORKER_URL` and `RELAY_TOKEN` in Script Properties
4. Deploy → Web app → Anyone → Copy `/exec` URL

### 3. Run Go Client

```bash
cd client
go run . -relay https://script.google.com/macros/s/YOUR_ID/exec -token yourtoken
# SOCKS5 now on localhost:1080
curl --proxy socks5://localhost:1080 https://example.com
```

## Build (pre-built binaries via GitHub Actions)

See [Releases](../../releases) — Linux/macOS/Windows amd64 + arm64 are built on every push to `main`.

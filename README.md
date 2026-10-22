# SENTINEL X v2.0 — Penetration Testing Platform

> **For authorized security testing only. Always obtain written permission before scanning any network.**

---

## Stack

| Layer     | Tech                          |
|-----------|-------------------------------|
| Runtime   | Node.js 18+ / Express 4       |
| NMAP      | System `nmap` binary          |
| Realtime  | WebSocket (`ws`)              |
| Parsing   | `xml2js` (NMAP XML output)    |
| Logging   | `winston`                     |
| Target OS | Windows, macOS, Linux (Kali or any Debian-based distro gets the extra scripted automation) |

---

## Quick Start

### Windows / macOS / any Linux (recommended)

```bash
cd sentinelx
npm run setup     # cross-platform: creates .env, installs deps, checks DB/nmap, runs migrations
npm start
```

Then open **http://127.0.0.1:3000** in a browser, or verify from the terminal:
```bash
curl http://127.0.0.1:3000/health
```

`npm run setup` (`scripts/setup.js`) is pure Node — no `bash` required — so it works the same on
Windows (cmd, PowerShell, Git Bash) as it does on macOS/Linux. It will tell you exactly what's
missing (Nmap, hashcat, PostgreSQL) and how to install each one for your OS; none of them are
required just to start exploring the dashboard — only to run real scans/cracks.

- **Nmap** (optional, for `/api/nmap/*`): https://nmap.org/download.html#windows on Windows,
  `brew install nmap` on macOS, your package manager on Linux. If it's not on PATH, set
  `NMAP_BINARY` in `.env` to its full path (e.g. `C:\Program Files (x86)\Nmap\nmap.exe`).
  Without it, the built-in `/api/recon/portscan` TCP connect scanner still works with zero setup.
- **hashcat** (optional, for GPU-accelerated cracking): https://hashcat.net/hashcat/. Without it,
  the dictionary and brute-force crack modes work natively in Node.
- **PostgreSQL** (optional — the app runs in-memory-only without it, just without persistence):
  official installer at https://www.postgresql.org/download/, or run it in Docker:
  `docker run -d -e POSTGRES_USER=sentinelx -e POSTGRES_PASSWORD=sentinelx -e POSTGRES_DB=sentinelx -p 5432:5432 postgres:16`

### Debian/Ubuntu/Kali with full root automation (legacy path)

```bash
cd sentinelx
sudo bash setup.sh   # installs nmap/postgres via apt, configures pg_hba.conf, sets up systemd
npm start
```

---

## Project Structure

```
sentinelx/
├── src/
│   ├── server.js               # Express + WebSocket bootstrap
│   ├── modules/
│   │   ├── nmapEngine.js       # Core NMAP engine (spawn, parse, queue)
│   │   ├── portScanner.js      # Built-in TCP connect scanner (no external binary)
│   │   ├── sslChecker.js       # TLS certificate/protocol inspector
│   │   ├── headerAudit.js      # HTTP security header audit
│   │   ├── hashCracker.js      # Dictionary / brute-force / hashcat cracking
│   │   ├── hashIdentifier.js   # Hash type fingerprinting
│   │   ├── wordlistManager.js  # Wordlist discovery, generation, mutation
│   │   └── aiAnalyst.js        # Claude-powered analyst (reports, CVE, attack chains)
│   ├── routes/
│   │   ├── nmap.js             # /api/nmap/* endpoints
│   │   ├── recon.js            # /api/recon/* endpoints (port scan, SSL, headers)
│   │   ├── scans.js            # /api/scans/* endpoints
│   │   ├── system.js           # /api/system/* endpoints
│   │   ├── hash.js             # /api/hash/* endpoints
│   │   ├── wordlists.js        # /api/wordlists/* endpoints
│   │   ├── ai.js                # /api/ai/* endpoints
│   │   ├── auth.js             # /api/auth/* endpoints (JWT)
│   │   └── engagements.js      # /api/engagements/* endpoints
│   ├── middleware/
│   │   ├── auth.js             # API key authentication
│   │   ├── jwtAuth.js          # JWT access/refresh tokens, RBAC
│   │   ├── rateLimiter.js      # Per-IP rate limiting
│   │   └── errorHandler.js     # Global error handler
│   ├── db/
│   │   ├── pool.js             # PostgreSQL connection pool
│   │   ├── migrate.js          # Migration runner
│   │   ├── repository.js       # Data-access layer
│   │   └── bridge.js           # Persists in-memory job events to the DB
│   └── utils/
│       ├── logger.js           # Winston logger
│       ├── md4.js              # Pure-JS MD4 (for NTLM)
│       └── binLocator.js       # Cross-platform nmap/hashcat binary resolution
├── reports/
│   └── nmap/                   # XML + TXT scan outputs
├── logs/                       # Application logs
├── scripts/
│   ├── setup.js                # Cross-platform setup (Windows/macOS/Linux) — no bash needed
│   └── db-setup.sh             # Linux/root DB automation (legacy path)
├── .env                        # Configuration
├── package.json
└── setup.sh                    # Debian/Ubuntu/Kali root installer (legacy path)
```

---

## Authentication

All `/api/*` requests require an API key. Set it in `.env`:

```env
API_KEY=your-secret-key
```

Send it via header (preferred):
```
X-API-Key: your-secret-key
```
Or `Authorization: Bearer your-secret-key`

---

## API Reference

### System

#### `GET /health`
No auth required. Returns platform status.
```json
{ "status": "online", "platform": "Sentinel X", "uptime": 142 }
```

#### `GET /api/system/info`
NMAP binary info, Node version, OS.

#### `GET /api/system/stats`
Live job counts, memory usage, load average.

---

### NMAP Engine

#### `POST /api/nmap/scan` — Start a scan

**Body:**
```json
{
  "target":    "192.168.1.0/24",
  "flags":     ["-sS", "-sV", "-O", "-T4"],
  "portRange": "1-65535",
  "label":     "Internal network sweep"
}
```

**Response `202`:**
```json
{
  "message": "Scan queued",
  "jobId":   "a1b2c3d4-...",
  "status":  "queued",
  "links": {
    "status": "/api/nmap/scan/a1b2c3d4-...",
    "output": "/api/nmap/scan/a1b2c3d4-.../output"
  }
}
```

---

#### `GET /api/nmap/scan/:id` — Job status + parsed results

```json
{
  "id":          "a1b2c3d4-...",
  "status":      "complete",
  "target":      "192.168.1.0/24",
  "startedAt":   "2025-12-18T12:03:44.000Z",
  "completedAt": "2025-12-18T12:07:11.000Z",
  "results": {
    "hostsUp": 12,
    "hostsTotal": 256,
    "hosts": [
      {
        "ip":        "192.168.1.5",
        "status":    "up",
        "hostnames": ["WIN-SRV01"],
        "os": [
          { "name": "Windows Server 2008", "accuracy": 98 }
        ],
        "ports": [
          {
            "portid":   445,
            "protocol": "tcp",
            "state":    "open",
            "service":  { "name": "microsoft-ds", "product": "Windows", "version": "2008" },
            "scripts":  [{ "id": "smb-vuln-ms17-010", "output": "VULNERABLE" }]
          }
        ],
        "openPortCount": 6
      }
    ]
  }
}
```

**Status values:** `queued` → `running` → `complete` | `error` | `cancelled` | `timeout`

---

#### `GET /api/nmap/scan/:id/output` — Raw stdout stream

```json
{
  "total": 47,
  "since": 0,
  "lines": [
    "Starting Nmap 7.94 ...",
    "Nmap scan report for 192.168.1.5",
    "Host is up (0.0012s latency).",
    "PORT    STATE SERVICE",
    "445/tcp open  microsoft-ds"
  ]
}
```

Poll with `?since=N` to get only new lines (long-poll or interval):
```
GET /api/nmap/scan/:id/output?since=20
```

---

#### `DELETE /api/nmap/scan/:id` — Cancel scan

Sends `SIGTERM` to the NMAP process, then `SIGKILL` after 3s.

```json
{ "message": "Scan cancelled", "jobId": "a1b2c3d4-..." }
```

To fully delete (cancel + remove files):
```
DELETE /api/nmap/scan/:id?action=delete
```

---

#### `GET /api/nmap/jobs` — List all jobs

```
GET /api/nmap/jobs?status=complete&limit=10&offset=0
```

---

#### `POST /api/nmap/validate` — Preview command without running

```json
{
  "target":    "10.0.0.1",
  "flags":     ["-sS", "-sV", "--script", "vuln", "-T4"],
  "portRange": "80,443,8080"
}
```

Response:
```json
{
  "valid":      true,
  "command":    "nmap -sS -sV --script vuln -T4 -p80,443,8080 10.0.0.1",
  "safeFlags":  ["-sS", "-sV", "--script", "vuln", "-T4"],
  "target":     "10.0.0.1",
  "ports":      "80,443,8080"
}
```

---

#### `GET /api/nmap/scan/:id/download/:fmt` — Download report

```
GET /api/nmap/scan/:id/download/xml
GET /api/nmap/scan/:id/download/txt
```

---

#### `GET /api/nmap/status` — NMAP binary health

```json
{
  "available":    true,
  "binary":       "/usr/bin/nmap",
  "version":      "7.94",
  "activeScans":  1,
  "queuedScans":  0
}
```

---

## WebSocket Real-Time Feed

Connect to `ws://127.0.0.1:3000/ws`

**Events received:**

| `type`           | Payload                                    |
|------------------|--------------------------------------------|
| `connected`      | Handshake confirmation                     |
| `scan_queued`    | `{ jobId, target, queueDepth }`            |
| `scan_started`   | `{ jobId, target, args }`                  |
| `scan_output`    | `{ jobId, line }` — every stdout line      |
| `scan_complete`  | `{ jobId, status, results }`               |
| `scan_error`     | `{ jobId, error }`                         |
| `scan_cancelled` | `{ jobId }`                                |

**Example (browser):**
```javascript
const ws = new WebSocket('ws://127.0.0.1:3000/ws');

ws.onmessage = ({ data }) => {
  const event = JSON.parse(data);
  if (event.type === 'scan_output') {
    console.log(`[${event.jobId}]`, event.line);
  }
  if (event.type === 'scan_complete') {
    console.log('Results:', event.results);
  }
};

// Start a scan
fetch('http://127.0.0.1:3000/api/nmap/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-API-Key': 'YOUR_KEY' },
  body: JSON.stringify({
    target: '192.168.1.0/24',
    flags:  ['-sS', '-sV', '-O', '-T4'],
    portRange: '1-1000',
  }),
});
```

---

## Allowed NMAP Flags

Only these flags pass the security sanitiser:

**Scan types:** `-sS -sT -sU -sN -sF -sX -sA -sW -sM -sV -sC -O -A`  
**Timing:** `-T0 -T1 -T2 -T3 -T4 -T5`  
**Discovery:** `-Pn -PE -PP -PS -PA -PU -n -R`  
**Output/misc:** `-v -vv --open --reason --traceroute -6`  
**Evasion:** `-f --badsum`  
**Value flags:** `--script -p --exclude --min-rate --max-rate --max-retries --host-timeout --data-length -D -S --spoof-mac --ttl --source-port --script-args`

Any unlisted flag is silently dropped with a warning log.

---

## Built-in Recon Tools (`/api/recon/*`) — no external binary required

These run on pure Node.js and work identically on Windows/macOS/Linux with
zero extra installs — useful on a fresh Windows machine before (or instead
of) installing Nmap/hashcat, and as a quick passive check anywhere.

#### `POST /api/recon/portscan` — TCP connect port scan

```json
{ "target": "192.168.1.10", "ports": "common", "concurrency": 200, "grabBanner": true }
```
`ports` accepts `"common"` (a curated list), `"all"` (1-65535), or an explicit
spec like `"22,80,443,8000-8100"`. Note this is a TCP *connect* scan only
(no SYN/stealth scans — those need raw sockets and Nmap). Broadcasts
`portscan_started` / `portscan_open` / `portscan_progress` / `portscan_complete`
over the same WebSocket feed as Nmap jobs.

- `GET /api/recon/portscan/:id` — job status + open ports
- `GET /api/recon/portscan/jobs` — list jobs
- `DELETE /api/recon/portscan/:id` — remove a job record

#### `POST /api/recon/ssl` — TLS certificate inspector

```json
{ "host": "example.com", "port": 443 }
```
Reports negotiated protocol/cipher, certificate validity window, self-signed
and hostname-mismatch detection, and an overall `grade` (`good`/`warning`/`poor`).

#### `POST /api/recon/headers` — HTTP security header audit

```json
{ "url": "https://example.com" }
```
Follows redirects, checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy and Permissions-Policy, flags fingerprinting headers
(`Server`, `X-Powered-By`), and returns a `score` out of 100.

---

## Environment Variables

| Variable              | Default                    | Description                     |
|-----------------------|----------------------------|---------------------------------|
| `PORT`                | `3000`                     | HTTP listen port                |
| `HOST`                | `127.0.0.1`                | Bind address                    |
| `API_KEY`             | —                          | Auth key for all API requests   |
| `NMAP_BINARY`         | auto-detected               | Path to nmap binary — only needed if auto-detection fails (see Quick Start) |
| `HASHCAT_BINARY`      | auto-detected               | Path to hashcat binary — optional, same auto-detection as above |
| `NMAP_OUTPUT_DIR`     | `./reports/nmap`           | Where XML/TXT reports are saved |
| `NMAP_MAX_CONCURRENT` | `3`                        | Max parallel scans              |
| `NMAP_TIMEOUT_MS`     | `300000`                   | Per-scan timeout (ms)           |
| `CORS_EXTRA_ORIGINS`  | —                          | Comma-separated extra allowed origins (localhost/127.0.0.1 on any port is always allowed) |
| `LOG_LEVEL`           | `info`                     | `debug` / `info` / `warn`      |
| `NODE_ENV`            | `development`              | `production` disables query auth|
| `ANTHROPIC_API_KEY`   | —                          | For AI Analyst module (`/api/ai/*`) |

---

## Roadmap

- [x] NMAP Engine + REST API
- [x] WebSocket real-time streaming
- [x] Job queue + cancellation
- [x] XML results parsing → JSON
- [x] Hash Cracker module (`/api/hash`) — dictionary, brute-force and hashcat modes
- [x] Wordlist Manager (`/api/wordlists`)
- [x] AI Analyst module (`/api/ai`)
- [x] Auth: JWT sessions + API key
- [x] PostgreSQL persistence layer
- [x] Built-in cross-platform recon tools (`/api/recon/*`): TCP port scanner, TLS inspector, HTTP header audit
- [ ] Topology graph builder (`/api/topology`)
- [ ] OSINT module — passive subdomain/DNS/WHOIS enumeration (frontend tab exists as a stub)
- [ ] Vulnerability report export (PDF/HTML) from `/api/engagements/:id/vulns`
- [ ] Exploit modules / payload generator — intentionally not built here; these cross from
      defensive/audit tooling into attack tooling and need a much more deliberate, scoped design
      (e.g. signed/approved module packs, strict engagement-scope enforcement) before they belong
      in an automated pipeline

> The frontend still has "Exploit Modules", "Payload Generator" and "DDoS Sim" nav tabs left over
> as UI stubs. They're intentionally unimplemented — see the note above.

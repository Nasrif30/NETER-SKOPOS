# NETER-SKOPOS — The Dark Mirror
## Portable MITM Proxy & Security Auditor

> EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY.  
> Do not intercept traffic you are not authorized to inspect.

---

### Overview

NETER-SKOPOS is a portable, self-contained MITM proxy and security auditor built on
[mitmproxy](https://mitmproxy.org/). It intercepts HTTP and HTTPS traffic, detects
exposed credentials, analyzes cookie security, and generates Obsidian-compatible
Markdown reports alongside JSON and HTML visualizations — all stored locally inside
the project folder with zero external dependencies.

---

### Features

| Feature | Description |
|---|---|
| HTTP/HTTPS interception | Full traffic capture including TLS via mitmproxy CA |
| Credential detection | Passwords, tokens, JWTs, AWS keys, PII, financial data |
| Cookie analysis | Secure, HttpOnly flag auditing |
| Plaintext HTTP detection | Alerts on unencrypted traffic |
| Session fingerprinting | Client IP + User-Agent hashing |
| Obsidian reports | Markdown reports with frontmatter, tables, connection maps |
| HTML dashboard | Dark-themed visualization with traffic timeline |
| JSON export | Full session data serialization |
| SQLite storage | Permanent local audit database |

---

### Quick Start

**Windows (batch):**
```
run.bat
```

**Windows (PowerShell):**
```
.\run.ps1
```

**Manual:**
```
mitmdump -s src\neter_skopos.py -p 8080
```

Then configure your browser or device to use `127.0.0.1:8080` as its HTTP proxy.

---

### Project Structure

```
neter_skopos/
  config/liminas.yaml          Configuration file
  config/keys/master.key       Auto-generated master key (gitignored)
  certs/auctoritas/            mitmproxy CA certificate store
  storage/speculum/audit.db    SQLite audit database
  storage/umbrae/              Raw capture storage
  storage/lumen/               Generated reports (MD, JSON, HTML)
  logs/neter_skopos.log        Debug and event log
  src/neter_skopos.py          Main proxy script (mitmproxy addon)
  src/modules/analyzer.py      Traffic & credential analysis engine
  src/modules/reporter.py      Report generation (MD, JSON, HTML)
  src/modules/storage.py       SQLite persistence layer
  docs/                        Documentation
  requirements.txt             Python dependencies
  run.bat                      Windows batch launcher
  run.ps1                      PowerShell launcher
```

---

### Installation

See [INSTALL.md](INSTALL.md) for step-by-step setup instructions.

### Usage

See [USAGE.md](USAGE.md) for configuration and usage examples.

---

### Legal Notice

This tool is intended for:
- Security research on networks and devices you own or have explicit written permission to test
- Educational demonstrations of network security concepts
- CTF (Capture The Flag) competitions

Unauthorized interception of network traffic is illegal in most jurisdictions.
The authors assume no liability for misuse.
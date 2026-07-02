# NETER-SKOPOS — Usage Guide

## Starting the Proxy

**Windows batch:**
```
run.bat
```

**PowerShell:**
```
.\run.ps1
```

**Direct (any platform with mitmproxy installed):**
```
mitmdump -s src\neter_skopos.py -p 8080
```

---

## Console Output

Once running, NETER-SKOPOS prints each intercepted request:

```
[->]  GET  http://example.com/login
[HTTP] PLAINTEXT detected: http://example.com/login
[CRED] CRITICAL password found in request_body
```

A periodic report is generated automatically every 5 requests (configurable).

---

## Configuration — liminas.yaml

All settings are in `config/liminas.yaml`. Key sections:

### Network
```yaml
network:
  listen_port: 8080        # Proxy listening port
  listen_host: "0.0.0.0"  # Bind address
```

### Analysis
```yaml
analysis:
  detect_credentials: true
  detect_pii: true
  detect_weak_cookies: true
  detect_plaintext_http: true
  detect_ssl_errors: true
  detect_auth_tokens: true
```

### Reporting
```yaml
reporting:
  generate_on_flow_count: 5   # Report every N requests
  export_to_json: true        # Also save JSON session data
  visualize_connections: true # Also save HTML visualization
```

### Logging
```yaml
logging:
  level: "DEBUG"   # DEBUG | INFO | WARNING | ERROR
  file: "./logs/neter_skopos.log"
```

---

## Output Files

All output is stored inside the project folder.

| Location | Contents |
|---|---|
| `storage/lumen/Security_Audit_*.md` | Obsidian Markdown report |
| `storage/lumen/Session_*.json` | Full session JSON export |
| `storage/lumen/Visualization_*.html` | Dark-theme HTML dashboard |
| `storage/speculum/audit.db` | SQLite database (all sessions) |
| `logs/neter_skopos.log` | Detailed event log |

---

## Understanding Reports

### Markdown Report Sections

| Section | Description |
|---|---|
| Frontmatter | YAML metadata for Obsidian |
| Executive Summary | Key findings from the session |
| Connection Map | ASCII graph of client to intercepted domains |
| Exposed Credentials | Table of all matched sensitive data |
| HTTP Traffic Log | Chronological request log |
| Plaintext HTTP Warnings | Unencrypted URLs detected |
| Cookie Analysis | Secure/HttpOnly flag status per cookie |
| What a Hacker Would See | Educational attacker perspective |
| Recommendations | Prioritized remediation steps |

### Risk Scoring

| Score Range | Level | Meaning |
|---|---|---|
| 60+ | CRITICAL | Active credential exposure, severe risk |
| 40-59 | HIGH | Significant security weaknesses found |
| 20-39 | MEDIUM | Some weaknesses, moderate risk |
| 0-19 | LOW | No major issues detected |

**Scoring factors:**

| Finding | Points |
|---|---|
| CRITICAL credential (password, JWT, AWS key) | +15 |
| HIGH severity credential (auth token, financial) | +10 |
| MEDIUM severity (PII, username) | +5 |
| Plaintext HTTP request | +5 each |
| Cookie missing Secure flag | +3 each |
| SSL error | +5 each |
| Session over 100 requests | +5 |

---

## Common Scenarios

### Auditing a Web Application

1. Start NETER-SKOPOS: `run.bat`
2. Configure browser proxy to `127.0.0.1:8080`
3. Browse the target web application normally
4. Open `storage/lumen/*.md` in Obsidian or any Markdown viewer
5. Review the HTML dashboard in `storage/lumen/*.html`

### Checking a Mobile Device

1. Connect mobile device to the same Wi-Fi network
2. Start NETER-SKOPOS: `run.bat`
3. On the mobile device, set Wi-Fi proxy to your PC's IP and port 8080
4. Install mitmproxy CA cert on the mobile device
5. Browse normally — traffic is captured automatically

### Viewing Historical Sessions

The SQLite database retains all sessions:
```
storage/speculum/audit.db
```

Use any SQLite browser (e.g., DB Browser for SQLite) or query directly:
```sql
SELECT session_key, client_ip, risk_level, risk_score, total_requests
FROM sessions
ORDER BY start_time DESC;
```

---

## Stopping

Press `Ctrl+C` in the terminal window running NETER-SKOPOS.
All data is already persisted to disk.

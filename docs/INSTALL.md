# NETER-SKOPOS — Installation Guide

## Requirements

| Requirement | Minimum Version |
|---|---|
| Python | 3.8+ |
| mitmproxy | 10.0.0+ |
| PyYAML | 6.0+ |
| rich | 13.0.0+ |
| cryptography | 41.0.0+ |

---

## Step 1 — Install Python

Download from https://www.python.org/downloads/

During installation on Windows, check **"Add Python to PATH"**.

Verify:
```
python --version
```

---

## Step 2 — Install Dependencies

From the project root directory:

```
pip install -r requirements.txt
```

Or install manually:
```
pip install mitmproxy>=10.0.0 pyyaml>=6.0 rich>=13.0.0 cryptography>=41.0.0
```

---

## Step 3 — First Run & CA Certificate

On first run, mitmproxy auto-generates a Certificate Authority (CA) certificate
in `certs/auctoritas/`. To intercept HTTPS traffic you must install this cert
as a trusted CA in your browser or operating system.

**Run NETER-SKOPOS once first:**
```
run.bat
```
or
```
mitmdump -s src\neter_skopos.py -p 8080
```

Then install the CA certificate found at:
```
%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer
```

### Windows — Install CA Certificate

1. Double-click `mitmproxy-ca-cert.cer`
2. Click "Install Certificate"
3. Select "Local Machine" > "Place all certificates in the following store"
4. Browse > "Trusted Root Certification Authorities"
5. Finish

### Browser — Install CA Certificate

Firefox: Settings > Privacy & Security > Certificates > Import

Chrome: Uses the Windows system store (follow Windows steps above)

---

## Step 4 — Configure Proxy

Set your browser or device to use:
```
Proxy: 127.0.0.1
Port:  8080
```

**Firefox:** Settings > General > Network Settings > Manual proxy configuration

**Chrome / Windows System:** Settings > System > Open proxy settings >
LAN settings > Use proxy server > Address: 127.0.0.1 Port: 8080

---

## Directory Permissions

Ensure the project directory is writable. NETER-SKOPOS writes to:
- `storage/speculum/audit.db`
- `storage/lumen/` (reports)
- `logs/neter_skopos.log`
- `config/keys/master.key`

---

## Troubleshooting

| Issue | Fix |
|---|---|
| `mitmdump: command not found` | Run `pip install mitmproxy` or use full path |
| HTTPS sites not loading | CA certificate not installed — see Step 3 |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| Permission denied on storage | Run as a user with write access to project folder |
| Port 8080 in use | Edit `config/liminas.yaml` and change `listen_port` |

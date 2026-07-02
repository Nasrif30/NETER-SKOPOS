# NETER-SKOPOS Commands Reference

This document provides a quick reference for all the essential commands needed to run, operate, and maintain the NETER-SKOPOS platform.

---

## 1. Initializing the Core Proxy Engine

You need to start the main intercept engine on port `8080`.

### Windows (PowerShell / CMD)
```powershell
# Navigate to the project root after cloning
cd neter_skopos

# Launch the proxy on port 8080
mitmdump -s src\neter_skopos.py -p 8080
```

### Linux / Kali / WSL
```bash
# Navigate to the project root after cloning
cd neter_skopos

# Launch the proxy on port 8080 (Ensure mitmproxy is installed via apt/pip)
mitmdump -s src/neter_skopos.py -p 8080
```

---

## 2. Launching the Live UI Dashboard

The UI dashboard reads the generated HTML reports from the `storage/lumen` directory and presents them in an interactive browser view.

### Windows (PowerShell / CMD)
```powershell
python scripts\launch_ui.py
```

### Linux / Kali / WSL
```bash
python3 scripts/launch_ui.py
```

---

## 3. Executing the Automated Network Audit

The auto-auditor script will automatically discover your default gateway, fire baseline assessment payloads, and trigger the proxy to intercept and generate a report.

### Windows (PowerShell / CMD)
```powershell
python scripts\auto_audit.py
```

### Linux / Kali / WSL
```bash
# Auto-discover routing via 'ip r' and fire payloads
python3 scripts/auto_audit.py

# Optional: Manually override the target IP (e.g., if WSL captures the wrong virtual switch)
python3 scripts/auto_audit.py 192.168.0.1
```

---

## 4. Resetting Data and Clearing the UI

If you want to clear the active dashboard and return it to the "Awaiting Data" state, you must delete the generated reports in the `storage/lumen/` directory.

### Windows (PowerShell / CMD)
```powershell
Remove-Item "storage\lumen\*" -Recurse -Force
```

### Linux / Kali / WSL
```bash
rm -rf storage/lumen/*
```

---

## 5. Troubleshooting: Ghost Processes

Sometimes the Python proxy process does not terminate cleanly when you press `Ctrl+C`, leaving port `8080` bound. If you receive a `[winerror 10048]` socket error, you can use the built-in kill script.

### Windows (PowerShell / CMD)
```powershell
# Hunts down and forcefully kills the process holding port 8080
.\scripts\kill_proxy.bat
```

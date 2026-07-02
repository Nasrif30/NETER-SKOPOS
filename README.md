# NETER-SKOPOS
**The Dark Mirror — Portable MITM Security Auditing Platform**

<img width="1457" height="731" alt="Screenshot 2026-07-03 032228" src="https://github.com/user-attachments/assets/e5e6f4ac-36a6-4174-a4f4-046c12f35867" />


---


<img width="1915" height="970" alt="Screenshot 2026-07-03 031433" src="https://github.com/user-attachments/assets/6c5cb786-3ad1-4e94-aeb7-70c943856e03" />


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

NETER-SKOPOS is a specialized, dark-themed Man-In-The-Middle (MITM) intercept proxy and automated security auditing tool. It is designed to identify plaintext traffic vulnerabilities, intercept exposed credentials, and generate dynamic force-directed network visualizations in real-time.

---

## Architecture Overview

NETER-SKOPOS operates via an explicit proxy configuration. Client traffic is voluntarily routed through port `8080`, where the core intercept engine analyzes the payloads, stores the findings locally, and updates a live security dashboard. 
<img width="2181" height="8192" alt="Client Device Traffic-2026-07-02-180045" src="https://github.com/user-attachments/assets/1000e08c-e74a-4214-923e-d7af09222953" />


## Features
- **Real-Time Traffic Analysis:** Intercepts HTTP/HTTPS flows and identifies sensitive data exposure (passwords, tokens, JWTs).
- **Automated Routing Audits:** Includes one-click scripts for auto-discovering network gateways and deploying baseline credential payloads.
- **Force-Directed Dashboard:** Generates an interactive, physics-based network graph (similar to Obsidian) visualizing client interactions with remote domains and exposed endpoints.
- **Obsidian-Ready Reporting:** Outputs detailed markdown reports containing traffic timelines, plaintext warnings, and security recommendations.
- **Zero-Dependency Storage:** Utilizes local SQLite and JSON files for completely portable execution without external database requirements.

---

## Installation

Clone the repository and ensure you have `mitmproxy` installed.

```bash
git clone https://github.com/yourusername/neter_skopos.git
cd neter_skopos
```

---

## Usage Guide

NETER-SKOPOS relies on a multi-terminal execution model. You will need three concurrent terminal sessions to fully operate the platform.

### 1. Initialize the Core Proxy Engine
Start the interception proxy on port 8080.

```bash
mitmdump -s src/neter_skopos.py -p 8080
```
<img width="1457" height="731" alt="image" src="https://github.com/user-attachments/assets/a149ca92-f0ac-43d1-ad3c-b3ba74ee9f99" />

*(Note: Screenshot of the proxy running in the terminal.)*

### 2. Launch the Live UI Dashboard
In a second terminal, launch the local dashboard server. This will automatically open your default web browser to monitor the active session.

```bash
python3 scripts/launch_ui.py
```
<img width="1897" height="903" alt="Screenshot 2026-07-03 031528" src="https://github.com/user-attachments/assets/9c55fdab-3cac-4f48-8acc-dc72deb18ff2" />
*(Note: Screenshot of the live interactive dashboard with no data.)*



<img width="1915" height="970" alt="Screenshot 2026-07-03 031433" src="https://github.com/user-attachments/assets/d0f4491d-59bb-483d-bbe6-831776dde918" />

<img width="1876" height="577" alt="Screenshot 2026-07-03 031446" src="https://github.com/user-attachments/assets/52a26ad8-9691-4609-9ee6-7fc6c61b3341" />

<img width="1880" height="686" alt="Screenshot 2026-07-03 031458" src="https://github.com/user-attachments/assets/fde84e40-0857-4329-bb89-0408e87e2ac7" />

<img width="1886" height="602" alt="Screenshot 2026-07-03 031508" src="https://github.com/user-attachments/assets/fa55a5c0-1296-45ac-bc74-21ba08fc98a7" />
*(Note: Screenshot of the live interactive dashboard with data report.)*

### 3. Execute the Automated Network Audit
In a third terminal, run the auto-discovery script. This script automatically detects your network gateway and fires baseline assessment payloads through the proxy.

```bash
python3 scripts/auto_audit.py
```
<img width="726" height="625" alt="image" src="https://github.com/user-attachments/assets/11d5252f-b0c0-4be3-8348-fd926bd3a0bd" />

*(Note: Screenshot of the auto-audit script execution.)*

---

## Resetting Data
To clear all historical intercept data and return the dashboard to a standby state, flush the `storage/lumen` directory:

```bash
# Linux / Mac / WSL
rm -rf storage/lumen/*

# Windows PowerShell
Remove-Item "storage\lumen\*" -Recurse -Force
```

## Documentation
For a complete breakdown of configuration options, database schemas, and advanced commands, refer to the accompanying documentation files in the repository root:
- `COMMANDS.md`


## Disclaimer
NETER-SKOPOS is intended strictly for authorized security research, CTF environments, and auditing of infrastructure you explicitly own. Do not use this tool on unauthorized networks.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

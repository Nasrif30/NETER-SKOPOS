# NETER-SKOPOS
**The Dark Mirror — Portable MITM Security Auditing Platform**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

NETER-SKOPOS is a specialized, dark-themed Man-In-The-Middle (MITM) intercept proxy and automated security auditing tool. It is designed to identify plaintext traffic vulnerabilities, intercept exposed credentials, and generate dynamic force-directed network visualizations in real-time.

---

## Architecture Overview

NETER-SKOPOS operates via an explicit proxy configuration. Client traffic is voluntarily routed through port `8080`, where the core intercept engine analyzes the payloads, stores the findings locally, and updates a live security dashboard. 

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
![Core Proxy Engine Execution](<IMAGE_PLACEHOLDER_PROXY>)
*(Note: Replace the placeholder above with a screenshot of the proxy running in the terminal.)*

### 2. Launch the Live UI Dashboard
In a second terminal, launch the local dashboard server. This will automatically open your default web browser to monitor the active session.

```bash
python3 scripts/launch_ui.py
```
![Live UI Dashboard](<IMAGE_PLACEHOLDER_UI>)
*(Note: Replace the placeholder above with a screenshot of the live interactive dashboard.)*

### 3. Execute the Automated Network Audit
In a third terminal, run the auto-discovery script. This script automatically detects your network gateway and fires baseline assessment payloads through the proxy.

```bash
python3 scripts/auto_audit.py
```
![Automated Network Audit](<IMAGE_PLACEHOLDER_AUDIT>)
*(Note: Replace the placeholder above with a screenshot of the auto-audit script execution.)*

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
- `1_PROJECT STRUCTURE.md`
- `2_CONFIG & MAIN PROXY.md`
- `3_ANALYZER MODULE.md`
- `4_REPORTER MODULE.md`
- `5_STORAGE & DATABASE.md`
- `6_LAUNCHERS & DOCS.md`

## Disclaimer
NETER-SKOPOS is intended strictly for authorized security research, CTF environments, and auditing of infrastructure you explicitly own. Do not use this tool on unauthorized networks.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

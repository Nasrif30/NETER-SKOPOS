#!/usr/bin/env python3
# NETER·SKOPOS - The Dark Mirror
# EDUCATIONAL USE ONLY - AUTHORIZED SECURITY TESTING
# Version: 1.0.0 - Portable Edition

import sys
import os
import json
import sqlite3
import re
import hashlib
import base64
import time
import yaml
import logging
import threading
import socket
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Any, Tuple
import urllib.parse

# Ensure src/ is on sys.path so module imports work from any working directory
_SRC_DIR = Path(__file__).resolve().parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

# Rich console
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

# MITM Proxy
from mitmproxy import http  # type: ignore
from mitmproxy.script import concurrent  # type: ignore

from modules.analyzer import TrafficAnalyzer
from modules.reporter import ReportGenerator
from modules.storage import StorageManager

# Force UTF-8 encoding for Rich console on Windows
import io
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
console = Console()

# ======================= ASCII BANNER =======================
BANNER = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣶⣾⣿⣿⣿⣿⣿⣶⡆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡏⢤⡎⣿⣿⢡⣶⢹⣧⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣶⣶⣇⣸⣷⣶⣾⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢨⣿⣿⣿⢟⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡏⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣜⠿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣷⣿⡿⣷⣮⣙⠿⣿⣿⣿⣿⣿⡄⠀
⠀⠀⠠⢄⣀⡀⠀⠀⠀⠀⠀⠈⠫⡯⢿⣿⣿⣿⣶⣯⣿⣻⣿⣿⠀
⠀⠀⠤⢆⠆⠈⠉⠳⠤⣄⡀⠀⠀⠀⠙⢻⣿⣿⠿⠿⠿⢻⣿⠙⠇
⠠⠤⠀⣉⣁⣢⣄⣀⣀⣤⣿⠷⠦⠤⣠⡶⠿⣟⠀⠀⠀⠀⠻⡀⠀
⠀⠀⠔⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠃⠃⠉⠉⠛⠛⠿⢷⡶⠀⠀
"""

class NeterSkopos:
    VERSION = "1.0.0"
    CODENAME = "SKOPOS"

    def __init__(self):
        self.project_root = self._get_project_root()

        # 1. Resolve all paths
        self.config_path   = self.project_root / 'config'
        self.speculum_path = self.project_root / 'storage' / 'speculum'
        self.umbrae_path   = self.project_root / 'storage' / 'umbrae'
        self.lumen_path    = self.project_root / 'storage' / 'lumen'
        self.certs_path    = self.project_root / 'certs' / 'auctoritas'
        self.logs_path     = self.project_root / 'logs'

        # 2. Create directories
        for path in [self.speculum_path, self.umbrae_path, self.lumen_path,
                     self.certs_path, self.config_path, self.logs_path]:
            path.mkdir(parents=True, exist_ok=True)

        # 3. Load config
        self.config = self._load_config()

        # 4. Init logging (must come before anything that uses self.logger)
        self._init_logging()

        # 5. Load master key
        self._load_master_key()

        # 6. Init database (uses self.logger)
        self.db_path = self.speculum_path / 'audit.db'
        self._init_database()

        # 7. Init modules
        self.storage  = StorageManager(self.db_path)
        self.analyzer = TrafficAnalyzer()
        self.reporter = ReportGenerator(self.lumen_path, self.project_root)

        # 8. Init session store
        self.sessions = defaultdict(lambda: {
            'flows': [],
            'credentials': [],
            'cookies': [],
            'headers': [],
            'domains': [],
            'plaintext': [],
            'ssl_errors': [],
            'websocket': [],
            'tcp_data': [],
            'dns_queries': [],
            'start_time': datetime.now(),
            'user_agent': None,
            'client_ip': None,
            'total_requests': 0,
            'total_volume': 0
        })

        # 9. Print banner last
        self._print_banner()

    def _get_project_root(self) -> Path:
        script_path = Path(__file__).resolve()
        current = script_path.parent
        while current != current.parent:
            if (current / 'config' / 'liminas.yaml').exists():
                return current
            if current.name == 'src':
                return current.parent
            current = current.parent
        return script_path.parent

    def _load_config(self) -> Dict:
        config_path = self.config_path / 'liminas.yaml'
        if config_path.exists():
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        return {}

    def _load_master_key(self) -> str:
        key_path = self.config_path / 'keys' / 'master.key'
        if key_path.exists():
            with open(key_path, 'r') as f:
                return f.read().strip()
        else:
            key = base64.b64encode(os.urandom(32)).decode()
            key_path.parent.mkdir(parents=True, exist_ok=True)
            with open(key_path, 'w') as f:
                f.write(key)
            return key

    def _init_logging(self):
        log_file = self.logs_path / 'neter_skopos.log'
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
        )
        self.logger = logging.getLogger('NeterSkopos')

    def _init_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.executescript('''
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_key TEXT UNIQUE NOT NULL,
                client_ip TEXT,
                user_agent TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                total_requests INTEGER DEFAULT 0,
                total_volume INTEGER DEFAULT 0,
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT,
                report_path TEXT
            );

            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_key TEXT NOT NULL,
                timestamp TIMESTAMP,
                method TEXT,
                url TEXT,
                host TEXT,
                path TEXT,
                protocol TEXT,
                headers TEXT,
                body TEXT,
                body_size INTEGER,
                is_encrypted INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_key TEXT NOT NULL,
                timestamp TIMESTAMP,
                credential_type TEXT,
                credential_key TEXT,
                credential_value TEXT,
                source TEXT,
                context TEXT,
                severity TEXT
            );

            CREATE TABLE IF NOT EXISTS cookies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_key TEXT NOT NULL,
                timestamp TIMESTAMP,
                cookie_name TEXT,
                cookie_value TEXT,
                domain TEXT,
                path TEXT,
                secure INTEGER DEFAULT 0,
                httponly INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_key TEXT NOT NULL,
                timestamp TIMESTAMP,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                host TEXT,
                url TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_requests_session ON requests(session_key);
            CREATE INDEX IF NOT EXISTS idx_credentials_session ON credentials(session_key);
            CREATE INDEX IF NOT EXISTS idx_cookies_session ON cookies(session_key);
            CREATE INDEX IF NOT EXISTS idx_connections_session ON connections(session_key);
        ''')
        conn.commit()
        conn.close()
        self.logger.info(f"Database initialized at {self.db_path}")

    def _print_banner(self):
        info_panel = Panel(
            f"[cyan]{BANNER}[/cyan]\n\n"
            f"[yellow]Version:[/yellow] {self.VERSION} - {self.CODENAME}\n"
            f"[yellow]Project Root:[/yellow] {self.project_root}\n"
            f"[yellow]Storage:[/yellow] {self.project_root}/storage\n"
            f"[yellow]Listening:[/yellow] port {self.config.get('network', {}).get('listen_port', 8080)}\n"
            f"[yellow]Reports:[/yellow] {self.lumen_path}\n"
            f"\n[red]PERMANENT STORAGE ENABLED - NO RESTRICTIONS[/red]\n"
            f"[blue]github.com/nasrif30[/blue]",
            title="[bold white]N E T E R · S K O P O S[/bold white]",
            subtitle="[italic]The Dark Mirror[/italic]",
            border_style="cyan"
        )
        console.print(info_panel)
        console.print("[green]Initialized successfully[/green]\n")

    def _get_session_key(self, flow) -> str:
        if flow.client_conn and flow.client_conn.address:
            client_ip = flow.client_conn.address[0]
        else:
            client_ip = "unknown"
        
        fingerprint_parts = [client_ip]
        for header, value in flow.request.headers.items():
            if header.lower() in ['user-agent', 'accept-language', 'accept-encoding']:
                fingerprint_parts.append(f"{header}:{value[:32]}")
        
        fingerprint_str = "|".join(fingerprint_parts)
        session_hash = hashlib.sha256(fingerprint_str.encode()).hexdigest()
        return f"{client_ip}_{session_hash[:16]}"

    def _store_connection(self, session_key: str, flow):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            src_ip = flow.client_conn.address[0] if flow.client_conn.address else "unknown"
            dst_ip = flow.request.host if flow.request.host else "unknown"
            c.execute('''
                INSERT INTO connections 
                (session_key, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, host, url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_key,
                datetime.now().isoformat(),
                src_ip,
                dst_ip,
                flow.client_conn.address[1] if flow.client_conn.address else 0,
                flow.request.port if hasattr(flow.request, 'port') else 443,
                flow.request.scheme,
                flow.request.host,
                flow.request.pretty_url[:500]
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Connection store error: {e}")

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            session_key = self._get_session_key(flow)
            session = self.sessions[session_key]

            if flow.client_conn and flow.client_conn.address:
                session['client_ip'] = flow.client_conn.address[0]
            if 'user-agent' in flow.request.headers:
                session['user_agent'] = flow.request.headers['user-agent'][:100]

            request_data = {
                'timestamp': datetime.now().isoformat(),
                'method': flow.request.method,
                'url': flow.request.pretty_url[:500],
                'host': flow.request.host,
                'headers': dict(flow.request.headers),
                'body': (flow.request.text or '')[:5000],
                'status': ''
            }

            session['flows'].append(request_data)
            session['total_requests'] += 1
            session['domains'].append(flow.request.host)

            # Store connection
            self._store_connection(session_key, flow)

            # Detect plaintext HTTP
            if flow.request.scheme != 'https':
                session['plaintext'].append(flow.request.pretty_url)
                console.print(f"[red]HTTP detected:[/red] {flow.request.pretty_url[:80]}")

            # Analyze credentials
            if flow.request.text:
                creds = self.analyzer.extract_credentials(
                    flow.request.text, 
                    'request_body',
                    flow.request.pretty_url,
                    flow.request.host
                )
                for cred in creds:
                    session['credentials'].append(cred)
                    self.storage.store_credential(session_key, cred)

            # Extract cookies
            for name, value in flow.request.cookies.items():
                cookie_data = {
                    'cookie_name': name,
                    'cookie_value': str(value)[:200],
                    'domain': flow.request.host,
                    'path': '/'
                }
                session['cookies'].append(cookie_data)
                self.storage.store_cookie(session_key, cookie_data)

            console.print(f"[blue]→[/blue] {flow.request.method} {flow.request.pretty_url[:80]}")

            # Generate periodic report
            if session['total_requests'] % 5 == 0:
                risk_level, risk_score, findings = self.analyzer.calculate_risk(session)
                report_path = self.reporter.generate_obsidian(
                    session_key, session, risk_level, risk_score, findings
                )
                self.storage.update_session(session_key, session, risk_score, risk_level, str(report_path))

        except Exception as e:
            self.logger.error(f"Request error: {e}")

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            session_key = self._get_session_key(flow)
            session = self.sessions[session_key]

            if flow.response and flow.response.text:
                creds = self.analyzer.extract_credentials(
                    flow.response.text,
                    'response_body',
                    flow.request.pretty_url,
                    flow.request.host
                )
                for cred in creds:
                    session['credentials'].append(cred)
                    self.storage.store_credential(session_key, cred)

                if hasattr(flow.response, 'status_code'):
                    if session['flows'] and isinstance(session['flows'][-1], dict):
                        session['flows'][-1]['status'] = flow.response.status_code

        except Exception as e:
            self.logger.error(f"Response error: {e}")

    def running(self):
        console.print(f"\n[green]NETER·SKOPOS active[/green]")
        console.print(f"[blue]Proxy:[/blue] localhost:{self.config.get('network', {}).get('listen_port', 8080)}")
        console.print(f"[blue]Reports:[/blue] {self.lumen_path}")
        console.print(f"[yellow]Press Ctrl+C to stop[/yellow]\n")

# Addon entry point
addons = [NeterSkopos()]

if __name__ == "__main__":
    from mitmproxy.tools.main import mitmdump
    sys.argv = ["mitmdump", "-p", "8080", "-s", __file__]
    mitmdump()
# src/modules/storage.py
# Storage Manager Module - NETER·SKOPOS
# The Dark Mirror — Portable Edition

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional


class StorageManager:
    """Handles all SQLite persistence for sessions, requests,
    credentials, cookies, and connections."""

    def __init__(self, db_path: Path):
        """
        Args:
            db_path: Absolute path to the SQLite database file.
        """
        self.db_path = db_path

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Return a WAL-mode connection with row_factory set."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    # ------------------------------------------------------------------
    # Credentials
    # ------------------------------------------------------------------

    def store_credential(self, session_key: str, credential: Dict) -> None:
        """Persist an intercepted credential record to the database.

        Args:
            session_key:  Unique session identifier.
            credential:   Dict with keys: type, key, value, source, context, severity.
        """
        try:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO credentials
                (session_key, timestamp, credential_type, credential_key,
                 credential_value, source, context, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_key,
                    datetime.now().isoformat(),
                    credential.get("type", ""),
                    credential.get("key", ""),
                    str(credential.get("value", ""))[:500],
                    credential.get("source", ""),
                    credential.get("context", "")[:500],
                    credential.get("severity", "MEDIUM"),
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Cookies
    # ------------------------------------------------------------------

    def store_cookie(self, session_key: str, cookie: Dict) -> None:
        """Persist an intercepted cookie record.

        Args:
            session_key: Unique session identifier.
            cookie:      Dict with keys: cookie_name, cookie_value, domain, path, secure, httponly.
        """
        try:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO cookies
                (session_key, timestamp, cookie_name, cookie_value,
                 domain, path, secure, httponly)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_key,
                    datetime.now().isoformat(),
                    cookie.get("cookie_name", ""),
                    str(cookie.get("cookie_value", ""))[:500],
                    cookie.get("domain", ""),
                    cookie.get("path", "/"),
                    1 if cookie.get("secure") else 0,
                    1 if cookie.get("httponly") else 0,
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------

    def store_request(self, session_key: str, flow_data: Dict) -> None:
        """Persist an HTTP request record.

        Args:
            session_key: Unique session identifier.
            flow_data:   Dict with keys: method, url, host, path, protocol,
                         headers, body, body_size, is_encrypted.
        """
        try:
            conn = self._connect()
            headers_json = json.dumps(flow_data.get("headers", {}))[:2000]
            conn.execute(
                """
                INSERT INTO requests
                (session_key, timestamp, method, url, host, path, protocol,
                 headers, body, body_size, is_encrypted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_key,
                    datetime.now().isoformat(),
                    flow_data.get("method", ""),
                    str(flow_data.get("url", ""))[:500],
                    flow_data.get("host", ""),
                    flow_data.get("path", ""),
                    flow_data.get("protocol", "http"),
                    headers_json,
                    str(flow_data.get("body", ""))[:5000],
                    flow_data.get("body_size", 0),
                    1 if flow_data.get("is_encrypted") else 0,
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def update_session(
        self,
        session_key: str,
        session_data: Dict,
        risk_score: int,
        risk_level: str,
        report_path: str,
    ) -> None:
        """Upsert a session summary record.

        Args:
            session_key:  Unique session identifier.
            session_data: In-memory session dict from NeterSkopos.sessions.
            risk_score:   Computed integer risk score 0–100.
            risk_level:   Textual risk level (CRITICAL / HIGH / MEDIUM / LOW).
            report_path:  Path to the generated Obsidian report file.
        """
        try:
            conn = self._connect()
            start_time = session_data.get("start_time", datetime.now())
            if isinstance(start_time, datetime):
                start_time = start_time.isoformat()

            conn.execute(
                """
                INSERT OR REPLACE INTO sessions
                (session_key, client_ip, user_agent, start_time, end_time,
                 total_requests, total_volume, risk_score, risk_level, report_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_key,
                    session_data.get("client_ip", "unknown"),
                    str(session_data.get("user_agent") or "")[:255],
                    start_time,
                    datetime.now().isoformat(),
                    len(session_data.get("flows", [])),
                    session_data.get("total_volume", 0),
                    risk_score,
                    risk_level,
                    report_path,
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_session_history(self, limit: int = 20) -> List[Dict]:
        """Retrieve the most recent session summaries from the database.

        Args:
            limit: Maximum number of session rows to return (default 20).

        Returns:
            List of session dicts ordered by start_time descending.
        """
        try:
            conn = self._connect()
            rows = conn.execute(
                """
                SELECT session_key, client_ip, user_agent, start_time, end_time,
                       total_requests, risk_score, risk_level, report_path
                FROM sessions
                ORDER BY start_time DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            conn.close()
            return [dict(row) for row in rows]
        except Exception:
            return []

    def get_credentials_for_session(self, session_key: str) -> List[Dict]:
        """Retrieve all credential records for a given session.

        Args:
            session_key: Unique session identifier.

        Returns:
            List of credential dicts.
        """
        try:
            conn = self._connect()
            rows = conn.execute(
                """
                SELECT credential_type, credential_key, credential_value,
                       source, context, severity, timestamp
                FROM credentials
                WHERE session_key = ?
                ORDER BY timestamp DESC
                """,
                (session_key,),
            ).fetchall()
            conn.close()
            return [dict(row) for row in rows]
        except Exception:
            return []

    def get_statistics(self) -> Dict:
        """Return high-level statistics across all sessions.

        Returns:
            Dict with keys: total_sessions, total_requests, total_credentials, total_cookies.
        """
        try:
            conn = self._connect()
            stats = {}
            stats["total_sessions"]    = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            stats["total_requests"]    = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            stats["total_credentials"] = conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
            stats["total_cookies"]     = conn.execute("SELECT COUNT(*) FROM cookies").fetchone()[0]
            conn.close()
            return stats
        except Exception:
            return {}
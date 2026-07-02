# src/modules/reporter.py
# Report Generator Module - NETER·SKOPOS
# The Dark Mirror — Portable Edition

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

class ReportGenerator:
    """Generates Obsidian-compatible Markdown reports, JSON exports,
    and dark-themed HTML network visualizations from intercepted session data."""

    def __init__(self, lumen_path: Path, project_root: Path):
        """
        Args:
            lumen_path:   Path to storage/lumen — where reports are written.
            project_root: Project root for relative path calculations.
        """
        self.lumen_path = lumen_path
        self.project_root = project_root
        self.lumen_path.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # PUBLIC: Obsidian Markdown Report
    # ------------------------------------------------------------------

    def generate_obsidian(
        self,
        session_key: str,
        session_data: Dict,
        risk_level: str,
        risk_score: int,
        findings: List[str],
    ) -> Path:
        """Generate a full Obsidian-compatible Markdown security audit report.

        Args:
            session_key:  Unique session identifier (IP + fingerprint hash).
            session_data: In-memory session dict from NeterSkopos.sessions.
            risk_level:   Textual risk level (CRITICAL / HIGH / MEDIUM / LOW).
            risk_score:   Integer risk score 0–100.
            findings:     List of human-readable finding strings.

        Returns:
            Path to the written .md report file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.lumen_path / f"Security_Audit_{timestamp}.md"

        flows        = session_data.get("flows", [])
        credentials  = session_data.get("credentials", [])
        cookies      = session_data.get("cookies", [])
        plaintext    = session_data.get("plaintext", [])
        domains      = list(set(session_data.get("domains", [])))
        client_ip    = session_data.get("client_ip", "unknown")
        user_agent   = (session_data.get("user_agent") or "unknown")[:120]

        # Risk badge emoji
        badge = {"CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "LOW": "[LOW]"}.get(risk_level, "[UNKNOWN]")

        # ---- YAML frontmatter ----
        md  = "---\n"
        md += f'title: "Security Audit Report — {timestamp}"\n'
        md += f'session: "{session_key}"\n'
        md += f'timestamp: "{datetime.now().isoformat()}"\n'
        md += f'risk_score: {risk_score}\n'
        md += f'risk_level: "{risk_level}"\n'
        md += f'generated_by: "NETER·SKOPOS"\n'
        md += f'version: "1.0.0"\n'
        md += f'tags: [security-audit, neter-skopos, {risk_level.lower()}]\n'
        md += "---\n\n"

        # ---- Header ----
        md += "# NETER·SKOPOS — Security Audit Report\n\n"
        md += f"> {badge} **Risk Level**: `{risk_level}` | **Score**: `{risk_score}/100`\n\n"
        md += "| Field | Value |\n|---|---|\n"
        md += f"| **Session** | `{session_key}` |\n"
        md += f"| **Client IP** | `{client_ip}` |\n"
        md += f"| **User-Agent** | `{user_agent}` |\n"
        md += f"| **Timestamp** | `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}` |\n"
        md += f"| **Total Requests** | `{len(flows)}` |\n"
        md += f"| **Unique Domains** | `{len(domains)}` |\n\n"
        md += "---\n\n"

        # ---- Executive Summary ----
        md += "## Executive Summary\n\n"
        if findings:
            for finding in findings[:15]:
                md += f"- {finding}\n"
        else:
            md += "_No critical findings detected in this session window._\n"
        md += "\n---\n\n"

        # ---- Connection Map ----
        md += "## Connection Map\n\n"
        md += "```\n"
        md += self._build_connection_graph(session_data)
        md += "\n```\n\n---\n\n"

        # ---- Exposed Credentials Table ----
        md += "## Exposed Credentials\n\n"
        if credentials:
            md += "| Severity | Type | Key | Value | Source |\n"
            md += "|---|---|---|---|---|\n"
            for cred in credentials[:50]:
                sev   = cred.get("severity", "MEDIUM")
                sev_icon = ""
                md += (
                    f"| {sev} "
                    f"| `{cred.get('type', '')}` "
                    f"| `{cred.get('key', '')[:40]}` "
                    f"| `{str(cred.get('value', ''))[:60]}` "
                    f"| {cred.get('source', '')} |\n"
                )
        else:
            md += "_No credentials intercepted._\n"
        md += "\n---\n\n"

        # ---- HTTP Traffic Log ----
        md += "## HTTP Traffic Log\n\n"
        if flows:
            md += "| # | Time | Method | URL | Status |\n"
            md += "|---|---|---|---|---|\n"
            for i, flow in enumerate(flows[:100], 1):
                ts     = flow.get("timestamp", "")[:19]
                method = flow.get("method", "")
                url    = flow.get("url", "")[:80]
                status = flow.get("status", "—")
                md += f"| {i} | `{ts}` | **{method}** | `{url}` | {status} |\n"
        else:
            md += "_No HTTP flows recorded._\n"
        md += "\n---\n\n"

        # ---- Plaintext HTTP Warnings ----
        md += "## Plaintext HTTP Warnings\n\n"
        if plaintext:
            md += "> WARNING: These URLs transmitted data without encryption.\n\n"
            for url in plaintext[:30]:
                md += f"- `{url[:120]}`\n"
        else:
            md += "_No plaintext HTTP detected — all traffic was encrypted._\n"
        md += "\n---\n\n"

        # ---- Cookie Analysis ----
        md += "## Cookie Analysis\n\n"
        if cookies:
            md += "| Name | Domain | Secure | HttpOnly |\n"
            md += "|---|---|---|---|\n"
            seen = set()
            for cookie in cookies[:50]:
                name   = cookie.get("cookie_name", "")
                domain = cookie.get("domain", "")
                key    = f"{name}@{domain}"
                if key in seen:
                    continue
                seen.add(key)
                secure   = "YES" if cookie.get("secure")   else "NO"
                httponly = "YES" if cookie.get("httponly") else "NO"
                md += f"| `{name[:40]}` | `{domain}` | {secure} | {httponly} |\n"
        else:
            md += "_No cookies intercepted._\n"
        md += "\n---\n\n"

        # ---- Educational Lesson ----
        md += "## What a Hacker Would See\n\n"
        md += self._build_educational_lesson(session_data, risk_level, credentials, plaintext)
        md += "\n---\n\n"

        # ---- Recommendations ----
        md += "## Recommendations\n\n"
        md += self._build_recommendations(session_data, credentials, plaintext, cookies)
        md += "\n---\n\n"

        # ---- Footer ----
        md += f"_Report generated by NETER·SKOPOS v1.0.0 — The Dark Mirror_  \n"
        md += f"_Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_\n"

        report_path.write_text(md, encoding="utf-8")

        # Side exports
        self._export_json(session_key, session_data)
        self._export_html_visualization(session_key, session_data)

        return report_path

    # ------------------------------------------------------------------
    # PUBLIC: Connection Graph (ASCII)
    # ------------------------------------------------------------------

    def _build_connection_graph(self, session_data: Dict) -> str:
        """Build an ASCII network map showing the client connecting to intercepted domains.

        Args:
            session_data: In-memory session dictionary.

        Returns:
            Multi-line ASCII art string.
        """
        client_ip = session_data.get("client_ip", "CLIENT")
        domains   = list(set(session_data.get("domains", [])))[:12]

        if not domains:
            return f"  [{client_ip}] — no connections recorded"

        lines = []
        lines.append(f"  ┌─────────────────────┐")
        lines.append(f"  |  CLIENT: {client_ip:<11} |")
        lines.append(f"  └──────────┬──────────┘")
        lines.append(f"             │  MITM INTERCEPT")
        lines.append(f"             ▼")

        for i, domain in enumerate(domains):
            connector = "├──▶" if i < len(domains) - 1 else "└──▶"
            lines.append(f"  {connector} {domain}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # PUBLIC: JSON Export
    # ------------------------------------------------------------------

    def _export_json(self, session_key: str, session_data: Dict) -> None:
        """Serialize the complete session data to a JSON file in lumen_path.

        Args:
            session_key:  Unique session identifier.
            session_data: In-memory session dictionary.
        """
        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = self.lumen_path / f"Session_{timestamp}.json"

        # Convert non-serializable types
        def _safe(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            return str(obj)

        export = {
            "session_key":    session_key,
            "exported_at":    datetime.now().isoformat(),
            "client_ip":      session_data.get("client_ip"),
            "user_agent":     session_data.get("user_agent"),
            "total_requests": session_data.get("total_requests", 0),
            "domains":        list(set(session_data.get("domains", []))),
            "flows":          session_data.get("flows", [])[:200],
            "credentials":    session_data.get("credentials", [])[:200],
            "cookies":        session_data.get("cookies", [])[:200],
            "plaintext":      session_data.get("plaintext", [])[:100],
        }

        try:
            output_path.write_text(
                json.dumps(export, indent=2, default=_safe),
                encoding="utf-8",
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # PUBLIC: HTML Visualization
    # ------------------------------------------------------------------

    def _export_html_visualization(self, session_key: str, session_data: Dict) -> None:
        """Generate a dark-themed HTML security dashboard with a force-directed
        brain map, credential alerts, and traffic timeline.

        Args:
            session_key:  Unique session identifier.
            session_data: In-memory session dictionary.
        """
        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = self.lumen_path / f"Visualization_{timestamp}.html"

        client_ip   = session_data.get("client_ip", "unknown")
        domains     = list(set(session_data.get("domains", [])))[:20]
        credentials = session_data.get("credentials", [])[:30]
        flows       = session_data.get("flows", [])[:50]
        plaintext   = session_data.get("plaintext", [])[:20]

        # Build graph data for the force-directed brain map
        # Nodes: client + domains + credential types + plaintext endpoints
        nodes = [{"id": "CLIENT", "label": client_ip, "type": "client", "r": 18}]
        edges = []
        seen_domains = set()
        seen_cred_types = set()

        for domain in domains:
            if domain not in seen_domains:
                seen_domains.add(domain)
                nodes.append({"id": f"domain_{domain}", "label": domain, "type": "domain", "r": 10})
                edges.append({"source": "CLIENT", "target": f"domain_{domain}"})

        for cred in credentials:
            ctype = cred.get("type", "unknown")
            node_id = f"cred_{ctype}"
            if node_id not in seen_cred_types:
                seen_cred_types.add(node_id)
                nodes.append({"id": node_id, "label": ctype.upper(), "type": "credential", "r": 8,
                              "severity": cred.get("severity", "MEDIUM")})
                # Link to domain if known
                host = cred.get("host", "")
                target = f"domain_{host}" if host and f"domain_{host}" in [n["id"] for n in nodes] else "CLIENT"
                edges.append({"source": target, "target": node_id})

        pt_unique = list(set(plaintext))[:6]
        for pt in pt_unique:
            label = pt[:30]
            node_id = f"pt_{hash(pt) % 99999}"
            nodes.append({"id": node_id, "label": label, "type": "plaintext", "r": 7})
            edges.append({"source": "CLIENT", "target": node_id})

        import json as _json
        nodes_json = _json.dumps(nodes)
        edges_json = _json.dumps(edges)

        # Build credential rows
        cred_rows = ""
        for cred in credentials:
            sev   = cred.get("severity", "MEDIUM")
            color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#44ff44"}.get(sev, "#aaa")
            cred_rows += (
                f'<tr>'
                f'<td><span style="color:{color}">{sev}</span></td>'
                f'<td><code>{cred.get("type","")}</code></td>'
                f'<td><code>{str(cred.get("key",""))[:40]}</code></td>'
                f'<td><code>{str(cred.get("value",""))[:60]}</code></td>'
                f'<td>{cred.get("source","")}</td>'
                f'</tr>\n'
            )

        flow_rows = ""
        for i, flow in enumerate(flows, 1):
            method = flow.get("method", "")
            url    = flow.get("url", "")[:80]
            ts     = flow.get("timestamp", "")[:19]
            status = flow.get("status", "—")
            flow_rows += (
                f'<tr>'
                f'<td>{i}</td>'
                f'<td><code>{ts}</code></td>'
                f'<td><strong>{method}</strong></td>'
                f'<td><code style="word-break:break-all">{url}</code></td>'
                f'<td>{status}</td>'
                f'</tr>\n'
            )

        pt_items = "".join(f"<li><code>{u[:120]}</code></li>\n" for u in plaintext) or "<li>None detected.</li>"

        if credentials:
            cred_table_html = (
                "<table><tr><th>Severity</th><th>Type</th><th>Key</th>"
                "<th>Value</th><th>Source</th></tr>"
                + cred_rows + "</table>"
            )
        else:
            cred_table_html = '<p style="color:#00ff88">No credentials intercepted.</p>'

        if flows:
            flow_table_html = (
                "<table><tr><th>#</th><th>Time</th><th>Method</th>"
                "<th>URL</th><th>Status</th></tr>"
                + flow_rows + "</table>"
            )
        else:
            flow_table_html = '<p style="color:#6b7280">No flows recorded.</p>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NETER-SKOPOS :: {session_key[:20]}</title>
<style>
  :root {{
    --bg: #08080f; --surface: #10101a; --card: #16162a;
    --border: #2a2a3d; --cyan: #00e5ff; --red: #ff4444;
    --orange: #ff8800; --yellow: #ffcc00; --green: #00ff88;
    --purple: #a78bfa; --text: #c8d0e0; --muted: #6b7280;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Courier New', monospace; background: var(--bg); color: var(--text); padding: 1.5rem; }}
  h1 {{ color: var(--cyan); font-size: 1.6rem; letter-spacing: 0.15em; margin-bottom: 0.2rem; }}
  h2 {{ color: var(--cyan); font-size: 1rem; letter-spacing: 0.1em; margin: 2rem 0 0.8rem;
        border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; }}
  .subtitle {{ color: var(--muted); font-size: 0.8rem; margin-bottom: 1.5rem; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.8rem; margin-bottom: 1.5rem; }}
  .meta-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 0.8rem; }}
  .meta-card .label {{ color: var(--muted); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em; }}
  .meta-card .value {{ color: var(--cyan); font-size: 1rem; margin-top: 0.2rem; word-break: break-all; }}
  .risk-badge {{ display: inline-block; padding: 0.25rem 1rem; border-radius: 999px;
                  font-weight: bold; font-size: 0.9rem; letter-spacing: 0.1em; margin-bottom: 1.5rem; }}
  .CRITICAL {{ background: rgba(255,68,68,0.15); color: #ff4444; border: 1px solid #ff4444; }}
  .HIGH     {{ background: rgba(255,136,0,0.15);  color: #ff8800; border: 1px solid #ff8800; }}
  .MEDIUM   {{ background: rgba(255,204,0,0.15);  color: #ffcc00; border: 1px solid #ffcc00; }}
  .LOW      {{ background: rgba(0,255,136,0.15);  color: #00ff88; border: 1px solid #00ff88; }}

  /* Brain map */
  #brain-map-wrap {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    position: relative;
    margin-bottom: 1.5rem;
    overflow: hidden;
  }}
  #brain-canvas {{ display: block; width: 100%; height: 420px; cursor: grab; }}
  #brain-canvas:active {{ cursor: grabbing; }}
  #tooltip {{
    position: absolute; pointer-events: none; background: rgba(10,10,20,0.92);
    border: 1px solid var(--cyan); color: var(--text); font-size: 0.75rem;
    padding: 0.3rem 0.6rem; border-radius: 4px; display: none;
    max-width: 220px; word-break: break-all;
  }}
  .legend {{ display: flex; gap: 1rem; flex-wrap: wrap; padding: 0.6rem 1rem;
              border-top: 1px solid var(--border); font-size: 0.72rem; color: var(--muted); }}
  .legend-item {{ display: flex; align-items: center; gap: 0.3rem; }}
  .dot {{ width: 10px; height: 10px; border-radius: 50%; }}

  table {{ width: 100%; border-collapse: collapse; margin-bottom: 1.5rem; font-size: 0.8rem; }}
  th {{ background: var(--card); color: var(--cyan); text-align: left; padding: 0.5rem 0.7rem;
        border: 1px solid var(--border); text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.05em; }}
  td {{ padding: 0.4rem 0.7rem; border: 1px solid var(--border); vertical-align: top; }}
  tr:nth-child(even) td {{ background: rgba(255,255,255,0.02); }}
  code {{ color: var(--cyan); background: rgba(0,229,255,0.07); padding: 0.1rem 0.25rem;
          border-radius: 3px; font-size: 0.78rem; }}
  ul {{ list-style: none; }}
  ul li {{ padding: 0.25rem 0; border-bottom: 1px solid var(--border); font-size: 0.8rem; }}
  .footer {{ margin-top: 2rem; color: var(--muted); font-size: 0.7rem; text-align: center; }}
</style>
</head>
<body>

<h1>NETER-SKOPOS — Security Dashboard</h1>
<p class="subtitle">The Dark Mirror &middot; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &middot; Session {session_key[:24]}</p>

<span class="risk-badge">{len(credentials)} Credentials | {len(domains)} Domains | {len(flows)} Requests</span>

<div class="meta-grid">
  <div class="meta-card"><div class="label">Client IP</div><div class="value">{client_ip}</div></div>
  <div class="meta-card"><div class="label">Total Requests</div><div class="value">{len(flows)}</div></div>
  <div class="meta-card"><div class="label">Unique Domains</div><div class="value">{len(domains)}</div></div>
  <div class="meta-card"><div class="label">Credentials Exposed</div><div class="value">{len(credentials)}</div></div>
  <div class="meta-card"><div class="label">Plaintext HTTP</div><div class="value">{len(plaintext)}</div></div>
  <div class="meta-card"><div class="label">Session</div><div class="value">{session_key[:20]}</div></div>
</div>

<h2>Network Brain Map</h2>
<div id="brain-map-wrap">
  <canvas id="brain-canvas"></canvas>
  <div id="tooltip"></div>
  <div class="legend">
    <div class="legend-item"><div class="dot" style="background:#00e5ff"></div> Client</div>
    <div class="legend-item"><div class="dot" style="background:#a78bfa"></div> Domain</div>
    <div class="legend-item"><div class="dot" style="background:#ff4444"></div> Credential</div>
    <div class="legend-item"><div class="dot" style="background:#ff8800"></div> Plaintext URL</div>
  </div>
</div>

<h2>Exposed Credentials</h2>
{cred_table_html}

<h2>Traffic Timeline</h2>
{flow_table_html}

<h2>Plaintext HTTP</h2>
<ul>{pt_items}</ul>

<div class="footer">
  Generated by <strong>NETER-SKOPOS v1.0.0</strong> &mdash; The Dark Mirror &middot;
  Session: <code>{session_key}</code>
</div>

<script>
const NODES = {nodes_json};
const EDGES = {edges_json};

const canvas = document.getElementById('brain-canvas');
const ctx    = canvas.getContext('2d');
const wrap   = document.getElementById('brain-map-wrap');
const tip    = document.getElementById('tooltip');

const NODE_COLOR = {{
  client:     '#00e5ff',
  domain:     '#a78bfa',
  credential: '#ff4444',
  plaintext:  '#ff8800',
}};
const SEV_COLOR = {{
  CRITICAL: '#ff4444', HIGH: '#ff8800', MEDIUM: '#ffcc00', LOW: '#00ff88'
}};

// Physics state
let W, H;
const state = {{}};   // id -> {{x,y,vx,vy}}
const K     = 0.0006; // spring stiffness
const REP   = 9000;   // repulsion
const DAMP  = 0.82;
const REST  = 140;    // rest length

function resize() {{
  const rect = wrap.getBoundingClientRect();
  W = canvas.width  = rect.width;
  H = canvas.height = 420;
  NODES.forEach(n => {{
    if (!state[n.id]) {{
      const angle = Math.random() * Math.PI * 2;
      const r     = 80 + Math.random() * 120;
      state[n.id] = {{
        x: W/2 + Math.cos(angle)*r,
        y: H/2 + Math.sin(angle)*r,
        vx: 0, vy: 0
      }};
    }}
  }});
  // Pin client to center
  if (NODES.find(n => n.type === 'client')) {{
    state['CLIENT'].x = W/2;
    state['CLIENT'].y = H/2;
  }}
}}

function simulate() {{
  // Repulsion
  NODES.forEach((a, i) => {{
    NODES.slice(i+1).forEach(b => {{
      const sa = state[a.id], sb = state[b.id];
      const dx = sb.x - sa.x, dy = sb.y - sa.y;
      const dist = Math.max(Math.sqrt(dx*dx + dy*dy), 1);
      const force = REP / (dist * dist);
      const fx = (dx/dist)*force, fy = (dy/dist)*force;
      if (a.type !== 'client') {{ sa.vx -= fx; sa.vy -= fy; }}
      if (b.type !== 'client') {{ sb.vx += fx; sb.vy += fy; }}
    }});
  }});
  // Spring attraction along edges
  EDGES.forEach(e => {{
    const sa = state[e.source], sb = state[e.target];
    if (!sa || !sb) return;
    const dx = sb.x - sa.x, dy = sb.y - sa.y;
    const dist = Math.max(Math.sqrt(dx*dx + dy*dy), 1);
    const force = K * (dist - REST);
    const fx = (dx/dist)*force, fy = (dy/dist)*force;
    if (NODES.find(n => n.id===e.source && n.type!=='client')) {{ sa.vx += fx; sa.vy += fy; }}
    if (NODES.find(n => n.id===e.target && n.type!=='client')) {{ sb.vx -= fx; sb.vy -= fy; }}
  }});
  // Integrate + damp + boundary
  NODES.forEach(n => {{
    if (n.type === 'client') return;
    const s = state[n.id];
    s.vx *= DAMP; s.vy *= DAMP;
    s.x = Math.max(n.r+10, Math.min(W - n.r - 10, s.x + s.vx));
    s.y = Math.max(n.r+10, Math.min(H - n.r - 10, s.y + s.vy));
  }});
}}

function draw() {{
  ctx.clearRect(0, 0, W, H);

  // Faint grid
  ctx.strokeStyle = 'rgba(42,42,61,0.4)';
  ctx.lineWidth   = 0.5;
  for (let x=0; x<W; x+=40) {{ ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,H); ctx.stroke(); }}
  for (let y=0; y<H; y+=40) {{ ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W,y); ctx.stroke(); }}

  // Edges
  EDGES.forEach(e => {{
    const sa = state[e.source], sb = state[e.target];
    if (!sa || !sb) return;
    const grad = ctx.createLinearGradient(sa.x, sa.y, sb.x, sb.y);
    grad.addColorStop(0, 'rgba(0,229,255,0.35)');
    grad.addColorStop(1, 'rgba(167,139,250,0.15)');
    ctx.beginPath();
    ctx.moveTo(sa.x, sa.y);
    ctx.lineTo(sb.x, sb.y);
    ctx.strokeStyle = grad;
    ctx.lineWidth   = 1;
    ctx.stroke();
  }});

  // Nodes
  NODES.forEach(n => {{
    const s = state[n.id];
    const color = n.severity ? SEV_COLOR[n.severity] || NODE_COLOR[n.type]
                              : NODE_COLOR[n.type] || '#888';

    // Glow
    const glow = ctx.createRadialGradient(s.x, s.y, 0, s.x, s.y, n.r * 3);
    glow.addColorStop(0, color + '44');
    glow.addColorStop(1, 'transparent');
    ctx.fillStyle = glow;
    ctx.beginPath();
    ctx.arc(s.x, s.y, n.r * 3, 0, Math.PI*2);
    ctx.fill();

    // Circle
    ctx.beginPath();
    ctx.arc(s.x, s.y, n.r, 0, Math.PI*2);
    ctx.fillStyle   = color + '22';
    ctx.fill();
    ctx.strokeStyle = color;
    ctx.lineWidth   = 1.5;
    ctx.stroke();

    // Label
    ctx.fillStyle  = color;
    ctx.font       = n.type === 'client' ? 'bold 11px Courier New' : '9px Courier New';
    ctx.textAlign  = 'center';
    ctx.textBaseline = 'middle';
    const label = n.label.length > 18 ? n.label.slice(0,17) + '...' : n.label;
    ctx.fillText(label, s.x, s.y);
  }});
}}

let hovered = null;
canvas.addEventListener('mousemove', e => {{
  const rect = canvas.getBoundingClientRect();
  const mx   = e.clientX - rect.left;
  const my   = e.clientY - rect.top;
  hovered = null;
  NODES.forEach(n => {{
    const s = state[n.id];
    const dx = mx - s.x, dy = my - s.y;
    if (Math.sqrt(dx*dx + dy*dy) < n.r + 6) {{
      hovered = n;
      tip.style.display = 'block';
      tip.style.left    = (e.clientX - wrap.getBoundingClientRect().left + 12) + 'px';
      tip.style.top     = (e.clientY - wrap.getBoundingClientRect().top + 12) + 'px';
      tip.textContent   = n.label + (n.severity ? ' [' + n.severity + ']' : '') + ' (' + n.type + ')';
    }}
  }});
  if (!hovered) tip.style.display = 'none';
}});

function loop() {{
  for (let i=0; i<3; i++) simulate();
  draw();
  requestAnimationFrame(loop);
}}

window.addEventListener('resize', resize);
resize();
loop();
</script>

</body>
</html>
"""
        try:
            output_path.write_text(html, encoding="utf-8")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # PRIVATE: Educational Lesson
    # ------------------------------------------------------------------

    def _build_educational_lesson(
        self,
        session_data: Dict,
        risk_level: str,
        credentials: List[Dict],
        plaintext: List[str],
    ) -> str:
        """Build the 'What a Hacker Would See' educational section.

        Args:
            session_data: Session dictionary.
            risk_level:   Overall risk level string.
            credentials:  List of intercepted credential dicts.
            plaintext:    List of plaintext HTTP URLs.

        Returns:
            Markdown string for the educational section.
        """
        lesson = ""
        if plaintext:
            lesson += (
                "**Unencrypted Traffic Detected**\n\n"
                "An attacker on the same network would see every byte of these HTTP requests "
                "in plaintext — usernames, passwords, session tokens, and all. "
                "This is the fundamental risk of HTTP vs HTTPS.\n\n"
                "> *Analogy: Sending a postcard instead of a sealed envelope. "
                "Every postal worker along the route can read it.*\n\n"
            )
        if credentials:
            types = list({c.get("type") for c in credentials})
            lesson += (
                f"**Credential Exposure** ({', '.join(types)})\n\n"
                "The intercepted credentials above represent real authentication material. "
                "In a real attack scenario, an adversary could:\n\n"
                "1. Replay captured session tokens to impersonate the user\n"
                "2. Use plaintext passwords directly on the target service\n"
                "3. Pivot to other services using credential stuffing\n"
                "4. Sell or leverage API keys for unauthorized cloud resource consumption\n\n"
                "> *OWASP A02:2021 — Cryptographic Failures covers exactly this risk.*\n\n"
            )
        if not lesson:
            lesson = (
                "No major weaknesses were observed in this session window. "
                "Traffic was encrypted and no sensitive data patterns were matched.\n\n"
                "> *Stay vigilant — security is a continuous practice, not a one-time check.*\n\n"
            )
        return lesson

    # ------------------------------------------------------------------
    # PRIVATE: Recommendations
    # ------------------------------------------------------------------

    def _build_recommendations(
        self,
        session_data: Dict,
        credentials: List[Dict],
        plaintext: List[str],
        cookies: List[Dict],
    ) -> str:
        """Build prioritised security recommendations based on session findings.

        Args:
            session_data: Session dictionary.
            credentials:  Intercepted credentials list.
            plaintext:    Plaintext HTTP URL list.
            cookies:      Intercepted cookies list.

        Returns:
            Markdown string with numbered recommendations.
        """
        recs = []
        n = 1

        if plaintext:
            recs.append(
                f"{n}. **Enforce HTTPS everywhere** — Redirect all HTTP traffic to HTTPS. "
                "Enable HSTS (`Strict-Transport-Security: max-age=31536000; includeSubDomains`)."
            )
            n += 1

        if credentials:
            recs.append(
                f"{n}. **Audit credential handling** — Review where passwords and tokens appear in "
                "request bodies, headers, and URLs. Use POST with HTTPS only. Never log credentials."
            )
            n += 1
            recs.append(
                f"{n}. **Rotate exposed secrets immediately** — Treat all intercepted API keys and "
                "tokens as compromised. Rotate them and revoke old values."
            )
            n += 1

        weak_cookies = [c for c in cookies if not c.get("secure")]
        if weak_cookies:
            recs.append(
                f"{n}. **Harden cookie attributes** — Set `Secure`, `HttpOnly`, and `SameSite=Strict` "
                "on all session cookies to prevent theft via network interception or XSS."
            )
            n += 1

        recs.append(
            f"{n}. **Implement Certificate Pinning** — Prevent MITM attacks on mobile or thick clients "
            "by pinning the expected TLS certificate or public key."
        )
        n += 1

        recs.append(
            f"{n}. **Enable Multi-Factor Authentication** — Even if credentials are stolen, MFA prevents "
            "immediate account compromise."
        )
        n += 1

        recs.append(
            f"{n}. **Monitor for anomalous traffic** — Deploy a SIEM or IDS to detect unusual request "
            "patterns, credential reuse, and off-hours access."
        )

        return "\n".join(recs) + "\n"

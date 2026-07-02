import os
import sys
import glob
import time
import webbrowser
from pathlib import Path

def get_latest_visualization(lumen_dir: Path) -> Path:
    """Find the most recently generated HTML visualization."""
    pattern = str(lumen_dir / "Visualization_*.html")
    files = glob.glob(pattern)
    
    if not files:
        return None
        
    # Sort by modification time, newest first
    files.sort(key=os.path.getmtime, reverse=True)
    return Path(files[0])

def generate_empty_dashboard(lumen_dir: Path) -> Path:
    """Generate a placeholder dashboard waiting for data."""
    empty_html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NETER-SKOPOS :: Awaiting Data</title>
<style>
  :root {
    --bg: #08080f; --surface: #10101a; --cyan: #00e5ff; --text: #c8d0e0;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { 
    font-family: 'Courier New', monospace; 
    background: var(--bg); 
    color: var(--text); 
    height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
  }
  .spinner {
    width: 60px;
    height: 60px;
    border: 3px solid rgba(0, 229, 255, 0.1);
    border-radius: 50%;
    border-top-color: var(--cyan);
    animation: spin 1s ease-in-out infinite;
    margin-bottom: 2rem;
  }
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
  h1 { color: var(--cyan); letter-spacing: 0.2em; font-size: 1.5rem; margin-bottom: 1rem; }
  p { color: #6b7280; font-size: 0.9rem; }
  
  .scanner {
    margin-top: 2rem;
    width: 300px;
    height: 2px;
    background: rgba(255,255,255,0.05);
    position: relative;
    overflow: hidden;
  }
  .scanner::after {
    content: '';
    position: absolute;
    top: 0; left: 0;
    width: 100px;
    height: 100%;
    background: var(--cyan);
    box-shadow: 0 0 10px var(--cyan);
    animation: scan 2s linear infinite;
  }
  @keyframes scan {
    0% { transform: translateX(-100px); }
    100% { transform: translateX(300px); }
  }
</style>
<script>
  // Simple polling to check for new reports
  setInterval(async () => {
    try {
      const response = await fetch('/api/check_latest?t=' + Date.now());
      if (response.ok) {
        const data = await response.json();
        if (data.latest && data.latest !== "empty_dashboard.html") {
          window.location.href = "/" + data.latest;
        }
      }
    } catch (e) {
      // Server might be down, ignore
    }
  }, 2000);
</script>
</head>
<body>
  <div class="spinner"></div>
  <h1>NETER-SKOPOS</h1>
  <p>System Ready. Waiting for target traffic interception...</p>
  <div class="scanner"></div>
  <p style="margin-top: 3rem; color: #444; font-size: 0.8rem;">
    github.com/nasrif30
  </p>
</body>
</html>
"""
    output_path = lumen_dir / "empty_dashboard.html"
    output_path.write_text(empty_html, encoding="utf-8")
    return output_path

if __name__ == "__main__":
    from http.server import SimpleHTTPRequestHandler, HTTPServer
    import json
    import threading
    
    # Setup paths
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    lumen_dir = project_root / "storage" / "lumen"
    lumen_dir.mkdir(parents=True, exist_ok=True)
    
    # Change working directory so SimpleHTTPRequestHandler serves from lumen
    os.chdir(lumen_dir)
    
    # Custom handler to add polling endpoint
    class DashboardHandler(SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/api/check_latest':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
                self.end_headers()
                
                latest = get_latest_visualization(lumen_dir)
                filename = latest.name if latest else ""
                
                self.wfile.write(json.dumps({"latest": filename}).encode())
                return
            
            # Default behavior
            return super().do_GET()
    
    PORT = 8081
    
    def start_server():
        with HTTPServer(("", PORT), DashboardHandler) as httpd:
            print(f"[NETER-SKOPOS] Dashboard UI Server running at http://localhost:{PORT}")
            httpd.serve_forever()
            
    # Start server in background thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Give server a moment to start
    time.sleep(1)
    
    # Find latest or create empty
    latest = get_latest_visualization(lumen_dir)
    if latest:
        target_url = f"http://localhost:{PORT}/{latest.name}"
        print(f"[NETER-SKOPOS] Found existing report. Opening...")
    else:
        empty = generate_empty_dashboard(lumen_dir)
        target_url = f"http://localhost:{PORT}/{empty.name}"
        print(f"[NETER-SKOPOS] No reports found. Opening waiting dashboard...")
        
    print(f"[NETER-SKOPOS] Opening browser: {target_url}")
    webbrowser.open(target_url)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\\n[NETER-SKOPOS] Shutting down UI server.")
        sys.exit(0)

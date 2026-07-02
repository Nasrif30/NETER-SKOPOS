# NETER-SKOPOS - PowerShell Launcher
# The Dark Mirror :: Portable MITM Proxy & Security Auditor v1.0.0

$banner = @"
 ================================================
  N E T E R - S K O P O S  ::  The Dark Mirror
  Portable MITM Proxy & Security Auditor v1.0.0
 ================================================
"@

Write-Host $banner -ForegroundColor Cyan

# ---- Verify Python ----
try {
    $pyVersion = python --version 2>&1
    Write-Host " [OK] $pyVersion" -ForegroundColor Green
} catch {
    Write-Host " [ERROR] Python not found. Install Python 3.8+ and add to PATH." -ForegroundColor Red
    Write-Host "         https://www.python.org/downloads/" -ForegroundColor Gray
    Read-Host "Press Enter to exit"
    exit 1
}

# ---- Verify mitmproxy ----
$mitmCheck = python -c "import mitmproxy; print('ok')" 2>&1
if ($mitmCheck -ne "ok") {
    Write-Host " [WARN] mitmproxy not installed. Installing dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host " [ERROR] Dependency installation failed." -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

Write-Host ""
Write-Host " [*] Starting NETER-SKOPOS..." -ForegroundColor Green
Write-Host " [*] Proxy   : http://127.0.0.1:8080" -ForegroundColor Blue
Write-Host " [*] Reports : storage\lumen\" -ForegroundColor Blue
Write-Host " [*] Database: storage\speculum\audit.db" -ForegroundColor Blue
Write-Host ""
Write-Host " [!] Configure your browser or device to use proxy 127.0.0.1:8080" -ForegroundColor Yellow
Write-Host " [!] For HTTPS: install the mitmproxy CA cert (auto-generated on first run)" -ForegroundColor Yellow
Write-Host ""
Write-Host " Press Ctrl+C to stop." -ForegroundColor DarkGray
Write-Host ""

# ---- Launch ----
mitmdump -s src\neter_skopos.py -p 8080 --ssl-insecure --set block_global=false

Write-Host ""
Write-Host " [*] NETER-SKOPOS stopped." -ForegroundColor Cyan
Read-Host "Press Enter to exit"
@echo off
setlocal EnableDelayedExpansion

echo.
echo  ================================================
echo   N E T E R - S K O P O S  ::  The Dark Mirror
echo   Portable MITM Proxy ^& Security Auditor v1.0.0
echo  ================================================
echo.

:: Check Python
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo  [ERROR] Python not found. Install Python 3.8+ and add it to PATH.
    echo  https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Check mitmproxy
python -c "import mitmproxy" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo  [WARN] mitmproxy not found. Installing dependencies...
    pip install -r requirements.txt
    if %ERRORLEVEL% neq 0 (
        echo  [ERROR] Dependency installation failed.
        pause
        exit /b 1
    )
)

echo  [*] Starting NETER-SKOPOS...
echo  [*] Proxy  : http://127.0.0.1:8080
echo  [*] Reports: storage\lumen\
echo  [*] Database: storage\speculum\audit.db
echo.
echo  [!] Configure your browser or device to use proxy 127.0.0.1:8080
echo  [!] For HTTPS: install the mitmproxy CA cert (auto-generated on first run)
echo.
echo  Press Ctrl+C to stop.
echo.

mitmdump -s src\neter_skopos.py -p 8080 --ssl-insecure --set block_global=false

echo.
echo  [*] NETER-SKOPOS stopped.
pause
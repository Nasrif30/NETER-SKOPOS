@echo off
setlocal enabledelayedexpansion

echo ==============================================
echo   NETER-SKOPOS :: Port 8080 Process Killer
echo ==============================================
echo.
echo Searching for processes using port 8080...

for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8080') do (
    set PID=%%a
    if "!PID!" NEQ "0" (
        echo [!] Found Ghost Process PID: !PID!
        echo [*] Terminating Process !PID!...
        taskkill /F /PID !PID! >nul 2>&1
        if !errorlevel! equ 0 (
            echo [+] Successfully killed PID !PID!
        ) else (
            echo [-] Failed to kill PID !PID!. Run as Administrator if needed.
        )
    )
)

echo.
echo Port 8080 should now be clear.
echo You can run 'mitmdump -s src\neter_skopos.py -p 8080' again.
echo.
pause

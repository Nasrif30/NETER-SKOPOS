# NETER-SKOPOS Router Audit Test Script
# Target: 192.168.0.1
# Run in NEW terminal while mitmdump is running

$proxy  = "http://127.0.0.1:8080"
$router = "http://192.168.0.1"

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  NETER-SKOPOS :: Router Audit"           -ForegroundColor Cyan
Write-Host "  Target: $router"                         -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Router admin index
Write-Host "[1] Router admin page - checking plaintext HTTP" -ForegroundColor Yellow
curl.exe -s -x $proxy "$router/" -o NUL
Write-Host ""

# 2. Common admin paths
Write-Host "[2] Probing common admin paths..." -ForegroundColor Yellow
$paths = @(
    "/", "/admin", "/login", "/login.html", "/login.cgi",
    "/cgi-bin/login.cgi", "/index.html", "/setup.cgi",
    "/userRpm/LoginRpm.htm", "/webpages/login.html"
)
foreach ($path in $paths) {
    $code = curl.exe -s -o NUL -w "%{http_code}" -x $proxy "$router$path"
    $color = "DarkGray"
    if ($code -eq "200") { $color = "Green" }
    elseif ($code -eq "301" -or $code -eq "302") { $color = "Yellow" }
    Write-Host "  [$code] $router$path" -ForegroundColor $color
}
Write-Host ""

# 3. Default credentials - ampersand escaped correctly
Write-Host "[3] Sending default credential login attempts over HTTP" -ForegroundColor Yellow
$defaultCreds = @(
    @{ user = "admin"; pass = "admin" },
    @{ user = "admin"; pass = "password" },
    @{ user = "admin"; pass = "1234" },
    @{ user = "admin"; pass = "" },
    @{ user = "root";  pass = "root" },
    @{ user = "root";  pass = "admin" },
    @{ user = "user";  pass = "user" }
)
foreach ($cred in $defaultCreds) {
    # Build form data without & in double-quoted string
    $user = $cred.user
    $pass = $cred.pass
    $formData = "username=${user}" + "&" + "password=${pass}"
    curl.exe -s -x $proxy "$router/login" -d $formData -o NUL
    curl.exe -s -x $proxy "$router/" -u "${user}:${pass}" -o NUL
    Write-Host "  Tried: $user / $pass" -ForegroundColor DarkGray
}
Write-Host ""

# 4. Response headers and cookies
Write-Host "[4] Capturing response headers and cookies..." -ForegroundColor Yellow
curl.exe -s -x $proxy "$router/" -I
Write-Host ""

# 5. API / config endpoints
Write-Host "[5] Probing config/status endpoints..." -ForegroundColor Yellow
$apiPaths = @(
    "/api/v1/status", "/api/status", "/status", "/info",
    "/config", "/cgi-bin/status", "/goform/getStatus", "/HNAP1/"
)
foreach ($path in $apiPaths) {
    $code = curl.exe -s -o NUL -w "%{http_code}" -x $proxy "$router$path"
    if ($code -ne "000") {
        $color = if ($code -eq "200") { "Green" } else { "DarkGray" }
        Write-Host "  [$code] $router$path" -ForegroundColor $color
    }
}
Write-Host ""

# 6. Flush to trigger report
Write-Host "[6] Flushing requests to trigger report generation..." -ForegroundColor Yellow
for ($i = 1; $i -le 3; $i++) {
    curl.exe -s -x $proxy "$router/" -o NUL
    Write-Host "  Probe $i done" -ForegroundColor DarkGray
}
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Audit complete." -ForegroundColor Green
Write-Host "  Reports: storage\lumen\Security_Audit_*.md" -ForegroundColor Green
Write-Host "  Visual:  storage\lumen\Visualization_*.html" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$reports = Get-ChildItem "storage\lumen\*.md" -ErrorAction SilentlyContinue |
           Sort-Object LastWriteTime -Descending
if ($reports) {
    $latest = $reports[0].FullName
    Write-Host "Latest report: $latest" -ForegroundColor White
}

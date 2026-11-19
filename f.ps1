# BEDROCK SS launcher - downloads the official release, verifies its SHA-256, then runs it.
# Short and readable on purpose. Source: https://github.com/ttvmalascapc-dotcom/Bedrock-SS-tool-Public
$ErrorActionPreference = 'Stop'
$base = 'https://github.com/ttvmalascapc-dotcom/Bedrock-SS-tool-Public/releases/latest/download'
$argsList = @()
if ('') { $argsList = ''.Split(' ') }

function Stop-Launch($step, $msg, $tip) {
    Write-Host ''
    Write-Host "  BEDROCK SS could not start. Step that failed: $step" -ForegroundColor Red
    Write-Host "  $msg" -ForegroundColor White
    if ($tip) { Write-Host "  What to try: $tip" -ForegroundColor Yellow }
    Write-Host '  If it keeps failing, take a screenshot of this window and send it to the staff member.' -ForegroundColor DarkGray
    Write-Host ''
}

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
Write-Host '  BEDROCK SS - downloading the official release ...' -ForegroundColor Cyan

$bytes = $null
$expected = ''
try {
    $wc = New-Object System.Net.WebClient
    $wc.Headers['User-Agent'] = 'BedrockSS-Launcher'
    $expected = (($wc.DownloadString("$base/BedrockSS.ps1.sha256")) -split '\s+')[0].Trim().ToLower()
    $bytes = $wc.DownloadData("$base/BedrockSS.ps1")
} catch {
    Stop-Launch 'download' $_.Exception.Message 'check your internet connection and that no firewall, VPN or school/work filter blocks github.com.'
    return
}
if ($expected -notmatch '^[0-9a-f]{64}$') {
    Stop-Launch 'verify' 'The published SHA-256 file is missing or invalid.' 'wait a minute and try again.'
    return
}
$sha = [System.Security.Cryptography.SHA256]::Create()
$actual = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLower()
if ($actual -ne $expected) {
    Stop-Launch 'verify' ("The downloaded file does NOT match the published SHA-256.`n  expected: $expected`n  received: $actual") 'do not run it. Try again in a minute.'
    return
}
Write-Host ('  Verified SHA-256 ' + $actual.Substring(0, 16) + '...') -ForegroundColor Green

# Only verified bytes are ever written to disk, into a folder this Windows user owns (not TEMP).
$dir = Join-Path $env:LOCALAPPDATA 'BedrockSS\run'
$file = ''
try {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Get-ChildItem -LiteralPath $dir -Filter '*.ps1' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } | Remove-Item -Force -ErrorAction SilentlyContinue
    $file = Join-Path $dir ('BedrockSS-' + $actual.Substring(0, 12) + '-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.ps1')
    [System.IO.File]::WriteAllBytes($file, $bytes)
} catch {
    Stop-Launch 'save' ("Could not write the file to $dir`n  " + $_.Exception.Message) 'Windows Security / antivirus or Controlled folder access may block new scripts. Run the diagnostic (see the staff member) to see exactly what is blocked.'
    return
}

try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $file @argsList
    if ($LASTEXITCODE -ne 0) {
        Stop-Launch 'run' ("The scanner stopped with exit code $LASTEXITCODE.") 'if you saw "running scripts is disabled" or "access denied", this PC blocks scripts (work/school policy, AppLocker or antivirus).'
    }
} catch {
    Stop-Launch 'run' $_.Exception.Message 'this PC may block scripts (work/school policy, AppLocker or antivirus).'
}

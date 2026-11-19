# BEDROCK SS diagnostic - checks every step the launcher needs and says which one is blocked. Changes nothing.
$ErrorActionPreference = 'Continue'
function Row($ok, $name, $detail) {
    $c = 'Green'; $t = 'PASS'
    if ($ok -eq $false) { $c = 'Red'; $t = 'FAIL' } elseif ($ok -eq $null) { $c = 'Yellow'; $t = 'INFO' }
    Write-Host ('  [' + $t + '] ' + $name) -ForegroundColor $c -NoNewline
    if ($detail) { Write-Host ('  ' + $detail) -ForegroundColor Gray } else { Write-Host '' }
}
Write-Host ''
Write-Host '  BEDROCK SS diagnostic' -ForegroundColor Cyan
Write-Host ''
Row $null 'PowerShell / host' ("$($PSVersionTable.PSVersion)  host=$($Host.Name)  user=$env:USERNAME")
$lm = [string]$ExecutionContext.SessionState.LanguageMode
Row ($lm -eq 'FullLanguage') 'Language mode (must be FullLanguage)' ($lm + $(if ($lm -ne 'FullLanguage') { '  <- AppLocker/WDAC restricts scripts on this PC' }))
$pol = (Get-ExecutionPolicy -List | ForEach-Object { $_.Scope.ToString() + '=' + $_.ExecutionPolicy.ToString() }) -join '  '
Row $null 'Execution policy' $pol
$mp = (Get-ExecutionPolicy -Scope MachinePolicy).ToString(); $up = (Get-ExecutionPolicy -Scope UserPolicy).ToString()
Row (($mp -eq 'Undefined') -and ($up -eq 'Undefined')) 'No group-policy script block' ("MachinePolicy=$mp UserPolicy=$up")

foreach ($pair in @(@('TEMP folder', $env:TEMP), @('LocalAppData\BedrockSS', (Join-Path $env:LOCALAPPDATA 'BedrockSS\diag')))) {
    $dir = $pair[1]; $f = Join-Path $dir ('diag_' + [guid]::NewGuid().ToString('N') + '.ps1')
    try {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-Content -LiteralPath $f -Value "Write-Output 'ok'" -Encoding ASCII
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f 2>&1
        $good = (($out | Out-String).Trim() -eq 'ok')
        Row $good ('Write AND run a script in ' + $pair[0]) $(if ($good) { $dir } else { ($out | Out-String).Trim() })
    } catch { Row $false ('Write/run in ' + $pair[0]) $_.Exception.Message }
    finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
}
$old = Join-Path $env:TEMP 'BedrockSS.ps1'
if (Test-Path -LiteralPath $old) {
    try { $fs = [IO.File]::Open($old, 'Open', 'ReadWrite', 'None'); $fs.Close(); Row $null 'Old %TEMP%\BedrockSS.ps1 exists' 'not locked (old launcher leftover)' }
    catch { Row $false 'Old %TEMP%\BedrockSS.ps1 is LOCKED or protected' $_.Exception.Message }
}
try {
    $r = [Net.WebRequest]::Create('https://github.com'); $r.Timeout = 10000; $resp = $r.GetResponse(); $resp.Close()
    Row $true 'Can reach github.com over HTTPS' ''
} catch [System.Net.WebException] {
    if ($_.Exception.Response) { Row $true 'Can reach github.com over HTTPS' ('HTTP ' + [int]$_.Exception.Response.StatusCode) } else { Row $false 'Can reach github.com over HTTPS' $_.Exception.Message }
} catch { Row $false 'Can reach github.com over HTTPS' $_.Exception.Message }
try {
    Add-Type -TypeDefinition 'public class BssDiag { public static int One() { return 1; } }' -ErrorAction Stop
    Row $true 'Compile helper code (Add-Type) - the scanner needs this' ''
} catch { Row $false 'Compile helper code (Add-Type) - the scanner needs this' $_.Exception.Message }
try { $cfa = (Get-MpPreference -ErrorAction Stop).EnableControlledFolderAccess; Row $null 'Defender Controlled folder access' ("value=$cfa (0 off, 1 on, 2 audit)") } catch { Row $null 'Defender settings' 'not readable here (third-party antivirus or no permission)' }
try { $av = (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { $_.displayName }) -join ', '; Row $null 'Antivirus products' $av } catch { Row $null 'Antivirus products' 'not readable' }
Write-Host ''
Write-Host '  Send a screenshot of this window to the staff member. Any red FAIL line is the blocker.' -ForegroundColor Cyan
Write-Host ''

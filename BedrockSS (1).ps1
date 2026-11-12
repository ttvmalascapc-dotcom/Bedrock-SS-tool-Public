<#
    BEDROCK SS - Screenshare Inspection Tool (terminal edition)
    Publisher: Malasca

    Read-only inspection. This tool never modifies, deletes, uploads or executes anything
    belonging to the inspected player. It writes only its own settings
    (%LOCALAPPDATA%\BedrockSS) and the evidence reports you choose to save.
    It does not collect passwords, cookies, browser data or personal documents.
#>

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

$script:Version   = '2.0.0'
$script:DbVersion = '2026.11.10'
$script:Publisher = 'Malasca'
$script:SelfPath  = ''
if ($PSCommandPath) { $script:SelfPath = $PSCommandPath }

$script:DataDir    = Join-Path $env:LOCALAPPDATA 'BedrockSS'
$script:ConfigPath = Join-Path $script:DataDir 'config.json'

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
$script:Cfg          = $null
$script:Findings     = New-Object System.Collections.ArrayList
$script:Observations = New-Object System.Collections.ArrayList
$script:Errors       = New-Object System.Collections.ArrayList
$script:Log          = New-Object System.Collections.ArrayList
$script:ModResults   = New-Object System.Collections.ArrayList
$script:SigCache     = @{}
$script:HashCache    = @{}
$script:SeenFiles    = New-Object 'System.Collections.Generic.Dictionary[string,bool]'
$script:SeenModules  = New-Object 'System.Collections.Generic.Dictionary[string,bool]'
$script:Mod          = $null
$script:Busy         = $false
$script:CancelAll    = $false
$script:NextId       = 1
$script:LastScan     = $null
$script:RunStart     = 0
$script:RunErrStart  = 0
$script:LastRows     = @()
$script:LastCols     = @()
$script:McVer        = ''
$script:NativeOk     = $false
$script:UseAnsi      = $false
$script:W            = 100
$script:G            = @{}

$script:UserDirs    = @('\Downloads\', '\Temp\', '\Desktop\', '\AppData\', '\Documents\', '\Users\Public\', '\ProgramData\', '\OneDrive\')
$script:GameDirs    = @('\WindowsApps\Microsoft.Minecraft', '\WindowsApps\Microsoft.GamingServices', '\XboxGames\Minecraft')
$script:SuspectDirs = @('\Downloads\', '\Desktop\', '\Temp\', '\Users\Public\')

# Indicator weights. Class rules (see Update-Finding):
#   HIGH       = known-bad hash, OR score >= 70 with at least two independent indicator kinds
#   SUSPICIOUS = score >= 30
#   CLEAN      = below threshold (kept as an observation)
# "Unsigned" or "unfamiliar" alone can never reach SUSPICIOUS.
$script:Weights = @{
    KnownHash = 100; KnownName = 40; MappedPE = 60; MissingOnDisk = 50; BadSignature = 35
    Unsigned = 15; UserFolder = 15; UnknownPublisher = 5; ScriptInGameData = 30; DllInGameData = 30
    InjectorTrace = 40; TraceCleared = 30; Impostor = 60; OddLocation = 15
}
$script:KindTitle = @{
    KnownHash        = 'Known-bad file hash'
    KnownName        = 'Known client/injector name'
    MappedPE         = 'Manually mapped PE image in memory'
    MissingOnDisk    = 'Loaded module missing from disk'
    BadSignature     = 'Invalid digital signature'
    Unsigned         = 'Unsigned file'
    UserFolder       = 'Loaded from user-writable folder'
    UnknownPublisher = 'Unrecognized publisher'
    ScriptInGameData = 'Lua script in Bedrock data folder'
    DllInGameData    = 'DLL in Bedrock data folder'
    InjectorTrace    = 'Injector/client execution trace'
    TraceCleared     = 'Execution traces missing'
    Impostor         = 'Name matches allowed client but not verified'
    OddLocation      = 'Loaded from outside standard install locations'
}
$script:KindSteps = @{
    KnownHash        = 'Confirm the hash independently (Get-FileHash) and check the entry label under Settings > Known indicator database.'
    KnownName        = 'Check where the file came from (creation time, download location) and whether it belongs to an allowed client.'
    MappedPE         = 'Keep Minecraft open. Look for an injector or client run just before the game started (Injection Investigation, Recent File Activity). Header-based detection can rarely misfire on legitimate software.'
    MissingOnDisk    = 'Check the Recycle Bin and recently deleted files on screen. A module deleted after loading is unusual.'
    BadSignature     = 'Open the file properties > Digital Signatures on screen and review why validation failed.'
    Unsigned         = 'Unsigned alone is not malicious. Check the product details and where the file came from.'
    UserFolder       = 'Check why a game-loaded DLL lives in a user-writable folder and compare with installed overlays.'
    UnknownPublisher = 'Look up the publisher. If it is legitimate, add it to the allowlist.'
    ScriptInGameData = 'Open the script on screen and read it. Check whether an installed client or launcher places scripts here.'
    DllInGameData    = 'Check the DLL origin and whether it belongs to an allowed client.'
    InjectorTrace    = 'Compare the execution time with when the player launched Minecraft and ask what the tool was.'
    TraceCleared     = 'Check whether the SysMain service was stopped or disabled, and when. Ask the player.'
    Impostor         = 'Compare the DLL hash against the official client release hash.'
    OddLocation      = 'Check why a game-loaded DLL sits outside Windows, Program Files and the game folder.'
}

# ---------------------------------------------------------------------------
# Native helpers (memory inspection + terminal VT mode). Read-only APIs only.
# ---------------------------------------------------------------------------
$script:NativeSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class BssNative {
    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int n);
    [DllImport("kernel32.dll")] static extern bool GetConsoleMode(IntPtr h, out uint m);
    [DllImport("kernel32.dll")] static extern bool SetConsoleMode(IntPtr h, uint m);
    public static bool EnableVt() {
        try {
            IntPtr h = GetStdHandle(-11);
            uint m;
            if (!GetConsoleMode(h, out m)) return false;
            if ((m & 4u) != 0) return true;
            return SetConsoleMode(h, m | 4u);
        } catch { return false; }
    }
}

public class MemProbe {
    [StructLayout(LayoutKind.Sequential)]
    struct MBI {
        public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
        public ushort PartitionId; public UIntPtr RegionSize; public uint State; public uint Protect; public uint Type;
    }
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint a, bool i, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern UIntPtr VirtualQueryEx(IntPtr h, IntPtr a, out MBI m, UIntPtr l);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, UIntPtr s, out UIntPtr r);

    IntPtr h = IntPtr.Zero;
    List<long[]> cand = new List<long[]>();
    public int RwxCount = 0;
    public int RegionCount = 0;

    static bool IsExec(uint p) { return (p & 0xF0u) != 0; }

    public int Open(int pid) {
        h = OpenProcess(0x0410u, false, pid);
        if (h == IntPtr.Zero) return Marshal.GetLastWin32Error();
        return 0;
    }

    public int Collect() {
        cand.Clear(); RwxCount = 0; RegionCount = 0;
        if (h == IntPtr.Zero) return 0;
        List<long[]> regs = new List<long[]>();
        long addr = 0;
        UIntPtr len = (UIntPtr)(uint)Marshal.SizeOf(typeof(MBI));
        while (addr >= 0 && addr < 0x7FFFFFFF0000L) {
            MBI m;
            if (VirtualQueryEx(h, (IntPtr)addr, out m, len) == UIntPtr.Zero) break;
            long size = (long)(ulong)m.RegionSize;
            RegionCount++;
            if (m.State == 0x1000u && m.Type != 0x1000000u) {
                regs.Add(new long[] { m.BaseAddress.ToInt64(), m.AllocationBase.ToInt64(), size, (long)m.Protect, (long)m.Type });
                if (m.Protect == 0x40u && m.Type == 0x20000u && size >= 0x10000) RwxCount++;
            }
            long next = m.BaseAddress.ToInt64() + size;
            if (next <= addr) break;
            addr = next;
        }
        Dictionary<long, bool> exec = new Dictionary<long, bool>();
        foreach (long[] r in regs) { if (IsExec((uint)r[3])) exec[r[1]] = true; }
        foreach (long[] r in regs) { if (r[0] == r[1] && exec.ContainsKey(r[1])) cand.Add(r); }
        return cand.Count;
    }

    public string Check(int i) {
        if (h == IntPtr.Zero || i < 0 || i >= cand.Count) return null;
        long[] r = cand[i];
        byte[] buf = new byte[0x400];
        int want = (int)Math.Min(r[2], (long)buf.Length);
        UIntPtr got;
        if (want < 0x40) return null;
        if (!ReadProcessMemory(h, (IntPtr)r[0], buf, (UIntPtr)(uint)want, out got)) return null;
        ulong g = (ulong)got;
        if (g < 0x40 || buf[0] != (byte)'M' || buf[1] != (byte)'Z') return null;
        int pe = BitConverter.ToInt32(buf, 0x3C);
        if (pe <= 0 || (ulong)(pe + 4) > g) return null;
        if (buf[pe] == (byte)'P' && buf[pe + 1] == (byte)'E' && buf[pe + 2] == 0 && buf[pe + 3] == 0)
            return "PE|" + r[0].ToString("X") + "|" + r[2].ToString() + "|" + r[3].ToString("X");
        return null;
    }

    public void Close() { if (h != IntPtr.Zero) { CloseHandle(h); h = IntPtr.Zero; } }
}
'@

function Initialize-Native {
    try {
        if (-not ('MemProbe' -as [type])) {
            Add-Type -TypeDefinition $script:NativeSource -Language CSharp -ErrorAction Stop
        }
        $script:NativeOk = $true
    } catch {
        $script:NativeOk = $false
        Write-Log 'ERROR' "Native helper failed to compile: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Logging / errors / observations
# ---------------------------------------------------------------------------
function Write-Log {
    param([string]$Level, [string]$Message)
    [void]$script:Log.Add([pscustomobject]@{ Time = (Get-Date).ToString('HH:mm:ss'); Level = $Level; Message = $Message })
}

function Add-ScanError {
    param([string]$Module, [string]$Target, [string]$Message)
    $access = ($Message -match 'denied|unauthorized|not have permission')
    $kind = 'Error'
    if ($access) { $kind = 'AccessDenied' }
    [void]$script:Errors.Add([pscustomobject]@{ Time = (Get-Date).ToString('HH:mm:ss'); Module = $Module; Target = $Target; Kind = $kind; Message = $Message })
    Write-Log 'WARN' "$Module / $Target : $Message"
}

function Add-Observation {
    param([string]$Module, [string]$Text, [string]$Path = '', [string]$When = '')
    if ($script:Observations.Count -ge 1000) { return }
    [void]$script:Observations.Add([pscustomobject]@{ Module = $Module; Text = $Text; Path = $Path; When = $When })
}

function Register-Inspected {
    param([string]$Path, [string]$Kind)
    $k = $Path.ToLower()
    if ($Kind -eq 'Module') { $script:SeenModules[$k] = $true } else { $script:SeenFiles[$k] = $true }
}

# ---------------------------------------------------------------------------
# Configuration (settings, allowlist, indicator database)
# ---------------------------------------------------------------------------
function New-DefaultConfig {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $allow = New-Object System.Collections.ArrayList
    $signers = @('Microsoft', 'NVIDIA', 'Advanced Micro Devices', 'AMD', 'Intel', 'Discord', 'OBS Project', 'Valve',
        'Overwolf', 'Realtek', 'Razer', 'Logitech', 'Corsair', 'SteelSeries', 'Guru3D', 'MSI', 'ASUS', 'Google',
        'Mozilla', 'Epic Games', 'Xbox', 'Streamlabs', 'Medal', 'Wallpaper Engine', 'Dolby', 'Waves Audio')
    foreach ($s in $signers) {
        [void]$allow.Add([pscustomobject]@{ Type = 'Signer'; Value = $s; Hash = ''; Note = 'Common overlay/driver publisher (valid signature required)' })
    }
    [void]$allow.Add([pscustomobject]@{ Type = 'Name'; Value = 'rtsshooks'; Hash = ''; Note = 'RivaTuner Statistics Server hook DLL (file name only)' })
    [void]$allow.Add([pscustomobject]@{ Type = 'Client'; Value = 'flarial'; Hash = ''; Note = 'Flarial main client DLL' })
    [void]$allow.Add([pscustomobject]@{ Type = 'Client'; Value = 'oderso'; Hash = ''; Note = 'Oderso main client DLL' })

    $tokens = @(
        [pscustomobject]@{ Token = 'onix';     Desc = 'Onix client' },
        [pscustomobject]@{ Token = 'horion';   Desc = 'Horion client' },
        [pscustomobject]@{ Token = 'nuvola';   Desc = 'Nuvola client' },
        [pscustomobject]@{ Token = 'zephyr';   Desc = 'Zephyr client' },
        [pscustomobject]@{ Token = 'fate';     Desc = 'Fate injector' },
        [pscustomobject]@{ Token = 'injector'; Desc = 'Generic injector name' }
    )

    [pscustomobject]@{
        Settings = [pscustomobject]@{
            ReportDir  = (Join-Path $desktop 'BedrockSS_Reports')
            RecentDays = 7
            FileDepth  = 3
            Ansi       = 'auto'
            Unicode    = $true
            Animations = $true
            LogLevel   = 'Normal'
            ScanMemory = $true
            ScanFiles  = $true
            ScanTraces = $true
        }
        Tokens   = @($tokens)
        Hashes   = @()
        Allow    = @($allow)
        Reviewed = @()
    }
}

function Import-Config {
    $def = New-DefaultConfig
    $script:Cfg = $def
    if (-not (Test-Path -LiteralPath $script:ConfigPath)) { return }
    try {
        $raw = Get-Content -LiteralPath $script:ConfigPath -Raw -Encoding UTF8
        $j = $raw | ConvertFrom-Json
        foreach ($p in @($def.Settings.PSObject.Properties)) {
            if ($j.Settings -and $j.Settings.PSObject.Properties[$p.Name]) {
                $def.Settings.($p.Name) = $j.Settings.($p.Name)
            }
        }
        foreach ($k in @('Tokens', 'Hashes', 'Allow', 'Reviewed')) {
            if ($j.PSObject.Properties[$k]) { $def.$k = @($j.$k) }
        }
    } catch {
        Write-Log 'WARN' "Settings file could not be read, defaults loaded: $($_.Exception.Message)"
    }
}

function Export-Config {
    try {
        if (-not (Test-Path -LiteralPath $script:DataDir)) { New-Item -ItemType Directory -Path $script:DataDir -Force | Out-Null }
        $script:Cfg | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8
        return $true
    } catch {
        Write-Log 'ERROR' "Settings could not be saved: $($_.Exception.Message)"
        return $false
    }
}

# ---------------------------------------------------------------------------
# UI layer (no detection logic in here)
# ---------------------------------------------------------------------------
$script:AnsiMap = @{
    Cyan = '96'; DarkCyan = '36'; Blue = '94'; Green = '92'; Yellow = '93'; Red = '91'
    Gray = '37'; DarkGray = '90'; White = '97'; Magenta = '95'
}

function Set-Glyphs {
    if ($script:Cfg.Settings.Unicode) {
        $script:G = @{
            H = [string][char]0x2500; V = [string][char]0x2502
            TL = [string][char]0x250C; TR = [string][char]0x2510; BL = [string][char]0x2514; BR = [string][char]0x2518
            LT = [string][char]0x251C; RT = [string][char]0x2524
            Full = [string][char]0x2588; Light = [string][char]0x2591
            Ok = [string][char]0x25CF; Warn = [string][char]0x25B2; Bad = [string][char]0x25A0; Info = [string][char]0x203A
            Ell = '..'
        }
    } else {
        $script:G = @{
            H = '-'; V = '|'; TL = '+'; TR = '+'; BL = '+'; BR = '+'; LT = '+'; RT = '+'
            Full = '#'; Light = '.'; Ok = '+'; Warn = '!'; Bad = 'x'; Info = '>'; Ell = '..'
        }
    }
}

function Initialize-Console {
    try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
    $script:UseAnsi = $false
    $mode = $script:Cfg.Settings.Ansi
    if ($mode -ne 'off') {
        $vt = $false
        if ($script:NativeOk) { try { $vt = [BssNative]::EnableVt() } catch { } }
        if ($env:WT_SESSION) { $vt = $true }
        if ($mode -eq 'on') { $vt = $true }
        $script:UseAnsi = $vt
    }
    Set-Glyphs
}

function Get-Width {
    try { return [Math]::Max(78, [Math]::Min([Console]::WindowWidth - 2, 132)) } catch { return 100 }
}

function Write-Seg {
    param([string]$Text, [string]$Color = 'Gray', [switch]$NoNewline)
    if ($script:UseAnsi) {
        $e = [string][char]27
        $t = $e + '[' + $script:AnsiMap[$Color] + 'm' + $Text + $e + '[0m'
        if ($NoNewline) { Write-Host $t -NoNewline } else { Write-Host $t }
    } else {
        if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline } else { Write-Host $Text -ForegroundColor $Color }
    }
}

function Format-Cut {
    param([string]$Text, [int]$Width)
    if ($null -eq $Text) { $Text = '' }
    if ($Width -lt 1) { return '' }
    if ($Text.Length -le $Width) { return $Text }
    if ($Width -le 2) { return $Text.Substring(0, $Width) }
    return $Text.Substring(0, $Width - 2) + $script:G.Ell
}

function Format-PathCut {
    param([string]$Text, [int]$Width)
    if ($null -eq $Text) { $Text = '' }
    if ($Width -lt 1) { return '' }
    if ($Text.Length -le $Width) { return $Text }
    if ($Width -le 3) { return $Text.Substring($Text.Length - $Width) }
    return $script:G.Ell + $Text.Substring($Text.Length - ($Width - 2))
}

function Format-ShaShort {
    param([string]$Sha)
    if (-not $Sha) { return '-' }
    return $Sha.Substring(0, 12) + $script:G.Ell
}

function Write-Rule {
    param([string]$Kind = 'mid')
    $g = $script:G
    $l = $g.LT; $r = $g.RT
    if ($Kind -eq 'top') { $l = $g.TL; $r = $g.TR }
    if ($Kind -eq 'bot') { $l = $g.BL; $r = $g.BR }
    Write-Seg ($l + ($g.H * ($script:W - 2)) + $r) 'DarkCyan'
}

function Write-Row {
    param([object[]]$Parts)   # each part: @('text','Color')
    $g = $script:G
    $used = 0
    foreach ($p in $Parts) { $used += $p[0].Length }
    $inner = $script:W - 4
    Write-Seg ($g.V + ' ') 'DarkCyan' -NoNewline
    foreach ($p in $Parts) { Write-Seg $p[0] $p[1] -NoNewline }
    $pad = $inner - $used
    if ($pad -lt 0) { $pad = 0 }
    Write-Seg ((' ' * $pad) + ' ' + $g.V) 'DarkCyan'
}

function Write-Status {
    param([string]$Level, [string]$Text)
    $c = 'Cyan'; $i = $script:G.Info
    switch ($Level) {
        'ok'   { $c = 'Green';  $i = $script:G.Ok }
        'warn' { $c = 'Yellow'; $i = $script:G.Warn }
        'bad'  { $c = 'Red';    $i = $script:G.Bad }
    }
    Write-Seg ('  ' + $i + ' ') $c -NoNewline
    Write-Seg $Text 'White'
}

function Get-Bar {
    param([int]$Percent, [int]$Width)
    if ($Percent -lt 0) { $Percent = 0 }
    if ($Percent -gt 100) { $Percent = 100 }
    $filled = [int][Math]::Floor($Width * $Percent / 100)
    return ($script:G.Full * $filled) + ($script:G.Light * ($Width - $filled))
}

function Get-ClassColor {
    param([string]$Class)
    switch ($Class) { 'HIGH' { return 'Red' } 'SUSPICIOUS' { return 'Yellow' } default { return 'Green' } }
}

function Get-ClassLabel {
    param([string]$Class, [bool]$Short = $false)
    switch ($Class) {
        'HIGH'       { if ($Short) { return 'HIGH CONF' } else { return 'HIGH CONFIDENCE' } }
        'SUSPICIOUS' { return 'SUSPICIOUS' }
        default      { return 'CLEAN' }
    }
}

$script:BannerText = @'
 ____  _____ ____  ____   ___   ____ _  __   ____  ____
| __ )| ____|  _ \|  _ \ / _ \ / ___| |/ /  / ___|/ ___|
|  _ \|  _| | | | | |_) | | | | |   | ' /   \___ \\___ \
| |_) | |___| |_| |  _ <| |_| | |___| . \    ___) |___) |
|____/|_____|____/|_| \_\\___/ \____|_|\_\  |____/|____/
'@

function Show-Header {
    param([string]$Title = '', [switch]$Full)
    Clear-Host
    $script:W = Get-Width
    if ($Full) {
        foreach ($line in ($script:BannerText -split "`r?`n")) {
            Write-Seg ('  ' + $line) 'Cyan'
            if ($script:Cfg.Settings.Animations) { Start-Sleep -Milliseconds 25 }
        }
        Write-Seg ('  Screenshare Inspection Tool  ' + $script:G.H + '  v' + $script:Version + '  ' + $script:G.H + '  Made by ' + $script:Publisher) 'DarkCyan'
        Write-Host ''
    } else {
        Write-Rule 'top'
        $right = 'v' + $script:Version + '  by ' + $script:Publisher
        $left = 'BEDROCK SS  ' + $script:G.Info + '  ' + $Title
        $space = ($script:W - 4) - $left.Length - $right.Length
        if ($space -lt 1) { $space = 1 }
        Write-Seg ($script:G.V + ' ') 'DarkCyan' -NoNewline
        Write-Seg 'BEDROCK SS' 'Cyan' -NoNewline
        Write-Seg ('  ' + $script:G.Info + '  ' + $Title) 'White' -NoNewline
        Write-Seg ((' ' * $space) + $right) 'DarkGray' -NoNewline
        Write-Seg (' ' + $script:G.V) 'DarkCyan'
        Write-Rule 'bot'
        Write-Host ''
    }
}

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Seg ('  ' + $script:G.Info + ' ' + $Text.ToUpper()) 'Cyan'
    Write-Seg ('  ' + ($script:G.H * ($script:W - 4))) 'DarkCyan'
}

function Write-Table {
    param([object[]]$Rows, [object[]]$Cols)
    $rowsArr = @($Rows)
    Write-Seg '  ' 'Gray' -NoNewline
    foreach ($c in $Cols) { Write-Seg ((Format-Cut $c.Title $c.Width).PadRight($c.Width) + '  ') 'DarkGray' -NoNewline }
    Write-Host ''
    Write-Seg '  ' 'Gray' -NoNewline
    foreach ($c in $Cols) { Write-Seg (($script:G.H * $c.Width) + '  ') 'DarkCyan' -NoNewline }
    Write-Host ''
    foreach ($r in $rowsArr) {
        Write-Seg '  ' 'Gray' -NoNewline
        foreach ($c in $Cols) {
            $val = ''
            if ($r.PSObject.Properties[$c.Key]) { $val = [string]$r.($c.Key) }
            $color = 'Gray'
            if ($c.Color) { $color = & $c.Color $val }
            $txt = $val
            if ($c.PathStyle) { $txt = Format-PathCut $val $c.Width } else { $txt = Format-Cut $val $c.Width }
            Write-Seg ($txt.PadRight($c.Width) + '  ') $color -NoNewline
        }
        Write-Host ''
    }
}

function Wait-Enter {
    param([string]$Text = 'Press Enter to continue')
    Write-Host ''
    Write-Seg ('  ' + $Text + ' ... ') 'DarkGray' -NoNewline
    [void](Read-Host)
}

function Read-Choice {
    param([string]$Prompt)
    Write-Seg ('  ' + $Prompt + ' ' + $script:G.Info + ' ') 'Cyan' -NoNewline
    $v = Read-Host
    if ($null -eq $v) { return '' }
    return $v.Trim()
}

# ---- live module progress panel -------------------------------------------
function Start-ScanModule {
    param([string]$Name, [int]$Total)
    $script:Mod = [pscustomobject]@{
        Name = $Name; Total = [Math]::Max($Total, 0); Done = 0; Allowed = 0; Target = 'preparing'
        Sw = [Diagnostics.Stopwatch]::StartNew(); Cancelled = $false; Top = -1; LastDraw = [long]-1000
        ErrStart = $script:Errors.Count; LastPct = -10
    }
    Write-Log 'INFO' "Module started: $Name"
    try {
        for ($i = 0; $i -lt 6; $i++) { Write-Host '' }
        $t = [Console]::CursorTop - 6
        if ($t -lt 0) { $t = 0 }
        $script:Mod.Top = $t
    } catch { $script:Mod.Top = -1 }
    Write-ModulePanel -Force
}

function Write-ModulePanel {
    param([switch]$Force, [switch]$Final)
    $m = $script:Mod
    if (-not $m) { return }
    $now = $m.Sw.ElapsedMilliseconds
    if (-not $Force -and -not $Final -and ($now - $m.LastDraw) -lt 80) { return }
    $m.LastDraw = $now
    $w = $script:W
    $pct = 0
    if ($m.Total -gt 0) { $pct = [int][Math]::Floor(($m.Done * 100.0) / $m.Total) }
    if ($Final -and -not $m.Cancelled) { $pct = 100 }
    if ($pct -gt 100) { $pct = 100 }
    $el = [TimeSpan]::FromMilliseconds($now).ToString('mm\:ss')
    $found = @($script:Findings | Where-Object { $_.Class -ne 'CLEAN' -and $_.Modules -contains $m.Name }).Count
    $errs = $script:Errors.Count - $m.ErrStart

    if ($m.Top -lt 0) {
        if ($pct -ge ($m.LastPct + 10) -or $Final) {
            $m.LastPct = $pct
            Write-Host ("  {0}: {1}% ({2}/{3})" -f $m.Name, $pct, $m.Done, $m.Total)
        }
        return
    }

    $barW = [Math]::Max(10, $w - 30)
    $bar = Get-Bar $pct $barW
    $status = 'Inspecting'
    if ($Final) { $status = 'Completed'; if ($m.Cancelled) { $status = 'Cancelled' } }
    $target = Format-PathCut $m.Target ($w - 16)
    try {
        [Console]::SetCursorPosition(0, $m.Top)
        Write-Seg (('  MODULE    ' + $m.Name + '  (' + $status + ')').PadRight($w)) 'Cyan'
        Write-Seg '  ' 'Gray' -NoNewline
        Write-Seg $bar 'Cyan' -NoNewline
        Write-Seg (('  {0,3}%  {1}/{2}' -f $pct, $m.Done, $m.Total).PadRight($w - 2 - $barW)) 'White'
        $fc = 'Green'; if ($found -gt 0) { $fc = 'Yellow' }
        $ec = 'Gray'; if ($errs -gt 0) { $ec = 'Yellow' }
        Write-Seg '  Findings ' 'DarkGray' -NoNewline
        Write-Seg ([string]$found).PadRight(6) $fc -NoNewline
        Write-Seg 'Errors ' 'DarkGray' -NoNewline
        Write-Seg ([string]$errs).PadRight(6) $ec -NoNewline
        Write-Seg 'Elapsed ' 'DarkGray' -NoNewline
        Write-Seg $el.PadRight([Math]::Max(1, $w - 40)) 'White'
        Write-Seg ('  Target    ' + $target).PadRight($w) 'Gray'
        $hint = '  Press Q to cancel this scan'
        if ($Final) { $hint = '' }
        Write-Seg $hint.PadRight($w) 'DarkGray'
    } catch { $m.Top = -1 }
}

function Step-ScanModule {
    param([string]$Target)
    $m = $script:Mod
    $m.Done++
    $m.Target = $Target
    if ($script:Cfg.Settings.LogLevel -eq 'Verbose') { Write-Log 'DEBUG' "Inspecting: $Target" }
    try {
        while ([Console]::KeyAvailable) {
            $k = [Console]::ReadKey($true)
            if ($k.Key -eq 'Q' -or $k.Key -eq 'Escape') { $m.Cancelled = $true; $script:CancelAll = $true }
        }
    } catch { }
    Write-ModulePanel
    return $m.Cancelled
}

function Stop-ScanModule {
    $m = $script:Mod
    if (-not $m) { return }
    $m.Sw.Stop()
    $m.Target = ''
    Write-ModulePanel -Final
    $found = @($script:Findings | Where-Object { $_.Class -ne 'CLEAN' -and $_.Modules -contains $m.Name }).Count
    $status = 'Completed'
    if ($m.Cancelled) { $status = 'Cancelled' }
    [void]$script:ModResults.Add([pscustomobject]@{
        Name = $m.Name; Items = $m.Done; Findings = $found; Allowlisted = $m.Allowed
        Errors = ($script:Errors.Count - $m.ErrStart); Seconds = [Math]::Round($m.Sw.Elapsed.TotalSeconds, 1); Status = $status
    })
    Write-Log 'INFO' "Module finished: $($m.Name) ($status, $($m.Done) items, $found findings)"
    $script:Mod = $null
}

# ---------------------------------------------------------------------------
# Detection support (no UI here)
# ---------------------------------------------------------------------------
function Test-PathLike {
    param([string]$Path, [string[]]$Patterns)
    foreach ($p in $Patterns) { if ($Path -like "*$p*") { return $true } }
    return $false
}

function Get-Sig {
    param([string]$Path)
    $k = $Path.ToLower()
    if ($script:SigCache.ContainsKey($k)) { return $script:SigCache[$k] }
    $res = [pscustomobject]@{ Status = 'Unknown'; Signer = '' }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $res.Status = $s.Status.ToString()
        if ($s.SignerCertificate -and $s.SignerCertificate.Subject -match 'CN=([^,]+)') { $res.Signer = $Matches[1].Trim('"') }
    } catch { }
    $script:SigCache[$k] = $res
    return $res
}

function Get-Sha {
    param([string]$Path)
    $k = $Path.ToLower()
    if ($script:HashCache.ContainsKey($k)) { return $script:HashCache[$k] }
    $h = ''
    try { $h = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { }
    $script:HashCache[$k] = $h
    return $h
}

function Get-FileFacts {
    param([string]$Path)
    $o = New-Object System.Collections.ArrayList
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        [void]$o.Add("Size: $($item.Length) bytes")
        [void]$o.Add("Created: $($item.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'))")
        [void]$o.Add("Modified: $($item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))")
        $vi = $item.VersionInfo
        if ($vi) {
            if ($vi.CompanyName)      { [void]$o.Add("Company: $($vi.CompanyName)") }
            if ($vi.FileDescription)  { [void]$o.Add("Description: $($vi.FileDescription)") }
            if ($vi.OriginalFilename) { [void]$o.Add("Original file name: $($vi.OriginalFilename)") }
        }
    } catch { }
    return @($o)
}

function Get-ScanTokens {
    $clients = @($script:Cfg.Allow | Where-Object { $_.Type -eq 'Client' } | ForEach-Object { $_.Value.ToLower() })
    return @($script:Cfg.Tokens | Where-Object { $clients -notcontains $_.Token.ToLower() })
}

function Find-Token {
    param([string]$Text)
    $l = $Text.ToLower()
    foreach ($t in @(Get-ScanTokens)) {
        if ($t.Token -and $l.Contains($t.Token.ToLower())) { return $t }
    }
    return $null
}

function Find-KnownHash {
    param([string]$Sha)
    if (-not $Sha) { return $null }
    foreach ($h in @($script:Cfg.Hashes)) { if ($h.Sha256 -and $h.Sha256.ToLower() -eq $Sha) { return $h } }
    return $null
}

function New-Indicator {
    param([string]$Kind, [string]$Text)
    [pscustomobject]@{ Kind = $Kind; Text = $Text; Weight = [int]$script:Weights[$Kind] }
}

function Test-Allowlist {
    param([string]$Name, [string]$Path, [string]$Sha, [string]$Signer, [string]$SigStatus)
    $res = [pscustomobject]@{ State = 'none'; Note = '' }
    $entries = @($script:Cfg.Allow)
    $lname = $Name.ToLower()
    $lpath = $Path.ToLower()

    foreach ($e in $entries) {
        if ($e.Hash -and $Sha -and ($e.Hash.ToLower() -eq $Sha)) {
            $res.State = 'allowed'; $res.Note = "SHA-256 is allowlisted ($($e.Note))"; return $res
        }
    }
    foreach ($e in $entries) {
        if ($e.Type -eq 'Client' -and $e.Value -and $lname.Contains($e.Value.ToLower())) {
            $v = $e.Value.ToLower()
            $hashed = @($entries | Where-Object { $_.Type -eq 'Client' -and $_.Value.ToLower() -eq $v -and $_.Hash }).Count -gt 0
            if ($hashed) {
                $res.State = 'impostor'
                $res.Note = "Named like $($e.Value) but its SHA-256 does not match any registered official hash."
                return $res
            }
            if (Test-PathLike $Path $script:SuspectDirs) {
                $res.State = 'impostor'
                $res.Note = "Named like $($e.Value) but located in Downloads/Desktop/Temp instead of an installed location."
                return $res
            }
            $res.State = 'allowed'
            $res.Note = "$($e.Note) (matched by file name only; register its SHA-256 to verify)"
            return $res
        }
    }
    if ($SigStatus -eq 'Valid' -and $Signer) {
        foreach ($e in $entries) {
            if ($e.Type -eq 'Signer' -and $e.Value -and ($Signer.IndexOf($e.Value, [StringComparison]::OrdinalIgnoreCase) -ge 0)) {
                $res.State = 'allowed'; $res.Note = "Valid signature from allowlisted publisher '$($e.Value)'"; return $res
            }
        }
    }
    foreach ($e in $entries) {
        if ($e.Type -eq 'Name' -and $e.Value -and $lname.Contains($e.Value.ToLower())) {
            $res.State = 'allowed'; $res.Note = "$($e.Note)"; return $res
        }
        if ($e.Type -eq 'Path' -and $e.Value -and $lpath.StartsWith($e.Value.ToLower())) {
            $res.State = 'allowed'; $res.Note = "Path is allowlisted ($($e.Note))"; return $res
        }
    }
    return $res
}

function Get-ReviewKey {
    param($F)
    return ($F.Key + '|' + $F.Sha256)
}

function Update-Finding {
    param($F)
    $score = 0
    foreach ($i in $F.Indicators) { $score += [int]$i.Weight }
    $kinds = @($F.Indicators | ForEach-Object { $_.Kind } | Select-Object -Unique)
    $F.Score = $score
    if ($kinds -contains 'KnownHash') { $F.Class = 'HIGH' }
    elseif ($score -ge 70 -and $kinds.Count -ge 2) { $F.Class = 'HIGH' }
    elseif ($score -ge 30) { $F.Class = 'SUSPICIOUS' }
    else { $F.Class = 'CLEAN' }

    $top = @($F.Indicators | Sort-Object Weight -Descending | Select-Object -First 1)[0]
    $F.Detection = $script:KindTitle[$top.Kind]
    if ($kinds.Count -gt 1) { $F.Detection = $F.Detection + ' (+' + ($kinds.Count - 1) + ' more)' }

    $lead = 'Below the reporting threshold; recorded as an observation only.'
    if ($F.Class -eq 'HIGH') { $lead = 'HIGH CONFIDENCE: multiple independently supported indicators (or a known-bad hash) are associated with unauthorized modification.' }
    if ($F.Class -eq 'SUSPICIOUS') { $lead = 'SUSPICIOUS: an anomaly that needs manual investigation. On its own this does not prove cheating.' }
    $titles = @($kinds | ForEach-Object { $script:KindTitle[$_] })
    $F.Explanation = $lead + ' Indicators: ' + ($titles -join '; ') + '. This is an automated interpretation of the observed facts, not proof.'

    $steps = New-Object System.Collections.ArrayList
    foreach ($k in $kinds) { if ($script:KindSteps.ContainsKey($k)) { [void]$steps.Add($script:KindSteps[$k]) } }
    [void]$steps.Add('Weigh this against the player''s explanation and what is visible on their screen before deciding.')
    $F.Steps = @($steps)
    $F.Reviewed = (@($script:Cfg.Reviewed) -contains (Get-ReviewKey $F))
}

function Add-Finding {
    param(
        [string]$Name, [string]$Path = '', [string]$Sha = '', [string]$Sig = '', [string]$Signer = '',
        $Indicators, [string[]]$Observed = @(), [string]$Key = '', [string]$Module = ''
    )
    if (-not $Module -and $script:Mod) { $Module = $script:Mod.Name }
    if (-not $Key) {
        if ($Path) { $Key = $Path.ToLower() } else { $Key = ("$Module|$Name").ToLower() }
    }
    $f = $null
    foreach ($x in $script:Findings) { if ($x.Key -eq $Key) { $f = $x; break } }
    if (-not $f) {
        $f = [pscustomobject]@{
            Id = $script:NextId; Key = $Key; Class = 'CLEAN'; Score = 0; Detection = ''; Name = $Name; Path = $Path
            Sha256 = $Sha; Signature = $Sig; Signer = $Signer; Detected = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Modules = (New-Object System.Collections.ArrayList); Indicators = (New-Object System.Collections.ArrayList)
            Observed = (New-Object System.Collections.ArrayList); Explanation = ''; Steps = @(); Reviewed = $false
        }
        $script:NextId++
        [void]$script:Findings.Add($f)
    }
    if ($Module -and ($f.Modules -notcontains $Module)) { [void]$f.Modules.Add($Module) }
    if ($Sha -and -not $f.Sha256) { $f.Sha256 = $Sha }
    if ($Sig -and (-not $f.Signature -or $f.Signature -eq 'Unknown')) { $f.Signature = $Sig; $f.Signer = $Signer }
    foreach ($i in @($Indicators)) {
        if (@($f.Indicators | Where-Object { $_.Kind -eq $i.Kind }).Count -eq 0) { [void]$f.Indicators.Add($i) }
    }
    foreach ($o in $Observed) { if ($f.Observed -notcontains $o) { [void]$f.Observed.Add($o) } }
    Update-Finding $f
}

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------
function Test-IsAdmin {
    try {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-BedrockProc {
    return @(Get-Process -Name 'Minecraft.Windows' -ErrorAction SilentlyContinue)
}

function Get-McVersion {
    if ($script:McVer) { return $script:McVer }
    try {
        $pkg = Get-AppxPackage -Name 'Microsoft.MinecraftUWP' -ErrorAction Stop | Select-Object -First 1
        if ($pkg) { $script:McVer = [string]$pkg.Version }
    } catch { }
    return $script:McVer
}

function Get-BedrockDataRoots {
    $pkg = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe'
    $roots = New-Object System.Collections.ArrayList
    foreach ($s in @('RoamingState', 'LocalState')) {
        $p = Join-Path $pkg $s
        if (Test-Path -LiteralPath $p) { [void]$roots.Add($p) }
    }
    return @($roots)
}

function Get-BedrockDataFiles {
    param([string[]]$Extensions)
    $out = New-Object System.Collections.ArrayList
    $depth = [int]$script:Cfg.Settings.FileDepth + 1
    foreach ($root in @(Get-BedrockDataRoots)) {
        foreach ($ext in $Extensions) {
            try {
                $files = @(Get-ChildItem -LiteralPath $root -Recurse -Depth $depth -File -Force -Filter ('*' + $ext) -ErrorAction SilentlyContinue)
                foreach ($f in $files) { if ($f.Extension.ToLower() -eq $ext) { [void]$out.Add($f) } }
            } catch { Add-ScanError 'File Scanner' $root $_.Exception.Message }
        }
    }
    return @($out)
}

function Get-BamEntries {
    $out = New-Object System.Collections.ArrayList
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
    if (-not (Test-Path $root)) { $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings' }
    if (-not (Test-Path $root)) { return @() }
    foreach ($sid in @(Get-ChildItem $root -ErrorAction SilentlyContinue)) {
        $key = Get-Item -LiteralPath $sid.PSPath
        foreach ($vn in $key.GetValueNames()) {
            $v = $key.GetValue($vn)
            if ($v -is [byte[]] -and $v.Length -ge 8) {
                $ft = [BitConverter]::ToInt64($v, 0)
                if ($ft -gt 0) { [void]$out.Add([pscustomobject]@{ Time = [DateTime]::FromFileTimeUtc($ft).ToLocalTime(); Path = $vn }) }
            }
        }
    }
    return @($out)
}

function Read-ScriptHead {
    param([string]$Path)
    $res = [pscustomobject]@{ Lines = @(); Text = '' }
    try {
        $fs = New-Object System.IO.FileStream($Path, 'Open', 'Read', 'ReadWrite')
        try {
            $buf = New-Object byte[] 65536
            $n = $fs.Read($buf, 0, $buf.Length)
            $txt = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
            $res.Text = $txt
            $lines = @($txt -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -First 3)
            $res.Lines = @($lines | ForEach-Object { Format-Cut $_ 100 })
        } finally { $fs.Dispose() }
    } catch { }
    return $res
}

# ---------------------------------------------------------------------------
# Shared DLL inspection (used by DLL / Signature / Hash scanners)
#   -Only All       : every indicator (name, location, signature, hash, missing file)
#   -Only Signature : digital-signature indicators only
#   -Only Hash      : known-hash indicator only
# ---------------------------------------------------------------------------
function Inspect-Dll {
    param([string]$Path, [string]$Name, [bool]$Loaded, [bool]$InData = $false, [string]$Only = 'All')
    $exists = $false
    try { $exists = Test-Path -LiteralPath $Path -PathType Leaf } catch { }
    $inSystem = $Path.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)
    $inGame = Test-PathLike $Path $script:GameDirs
    $userW = Test-PathLike $Path $script:UserDirs
    $added = (-not $inSystem) -and (-not $inGame)
    $kindReg = 'File'
    if ($Loaded) { $kindReg = 'Module' }
    Register-Inspected $Path $kindReg

    $sigStatus = 'Unknown'; $signer = ''; $sha = ''
    if ($exists) {
        $sg = Get-Sig $Path
        $sigStatus = $sg.Status; $signer = $sg.Signer
        if ($added -or $InData -or $Only -eq 'Hash') { $sha = Get-Sha $Path }
    }

    $ind = New-Object System.Collections.ArrayList

    if ($exists -and ($added -or $InData)) {
        $al = Test-Allowlist -Name $Name -Path $Path -Sha $sha -Signer $signer -SigStatus $sigStatus
        if ($al.State -eq 'allowed') {
            if ($script:Mod) { $script:Mod.Allowed++ }
            Add-Observation $script:Mod.Name "Allowlisted: $Name - $($al.Note)" $Path
            return
        }
        if ($al.State -eq 'impostor') { [void]$ind.Add((New-Indicator 'Impostor' $al.Note)) }
    }

    if ($Only -eq 'All' -or $Only -eq 'Signature') {
        if ($exists) {
            switch ($sigStatus) {
                'Valid' { if ($added) { [void]$ind.Add((New-Indicator 'UnknownPublisher' "Valid signature from '$signer' (publisher not on the allowlist).")) } }
                'NotSigned' { [void]$ind.Add((New-Indicator 'Unsigned' 'File has no digital signature.')) }
                'NotSupportedFileFormat' { }
                'Unknown' { }
                default { [void]$ind.Add((New-Indicator 'BadSignature' "Signature check returned '$sigStatus'.")) }
            }
        }
    }

    if ($Only -eq 'All') {
        if ($Loaded -and -not $exists) {
            [void]$ind.Add((New-Indicator 'MissingOnDisk' 'The module is loaded in Minecraft but its file is no longer on disk.'))
        }
        $tok = Find-Token $Path
        if ($tok -and -not ($sigStatus -eq 'Valid' -and ($inSystem -or $inGame))) {
            [void]$ind.Add((New-Indicator 'KnownName' "Path/name matches indicator '$($tok.Token)' ($($tok.Desc))."))
        }
        if ($Loaded -and $userW -and $exists -and -not $InData) {
            [void]$ind.Add((New-Indicator 'UserFolder' 'Module is loaded from a user-writable folder.'))
        }
        if ($Loaded -and $exists -and $added -and -not $InData -and -not $userW) {
            if (-not (Test-PathLike $Path @('\Program Files\', '\Program Files (x86)\'))) {
                [void]$ind.Add((New-Indicator 'OddLocation' 'Module is loaded from outside Windows, Program Files and the game folder.'))
            }
        }
        if ($InData -and -not $Loaded) {
            [void]$ind.Add((New-Indicator 'DllInGameData' 'A DLL is stored inside the Bedrock data folder (not a normal Minecraft file).'))
        }
    }

    if ($Only -eq 'All' -or $Only -eq 'Hash') {
        $kh = Find-KnownHash $sha
        if ($kh) { [void]$ind.Add((New-Indicator 'KnownHash' "SHA-256 matches known-indicator entry: $($kh.Label).")) }
    }

    if ($ind.Count -gt 0) {
        $obs = New-Object System.Collections.ArrayList
        $loadedText = 'File on disk (not loaded in the inspected process)'
        if ($Loaded) { $loadedText = 'Module loaded in Minecraft.Windows.exe' }
        [void]$obs.Add("Type: $loadedText")
        [void]$obs.Add("Signature: $sigStatus$(if ($signer) { ' - ' + $signer })")
        if ($exists) { foreach ($x in @(Get-FileFacts $Path)) { [void]$obs.Add($x) } }
        Add-Finding -Name $Name -Path $Path -Sha $sha -Sig $sigStatus -Signer $signer -Indicators $ind -Observed @($obs)
    }
}

# ---------------------------------------------------------------------------
# Scan modules
# ---------------------------------------------------------------------------
function Invoke-DllScan {
    param([string]$Only = 'All', [string]$ModuleName = 'DLL Scanner')
    Start-ScanModule $ModuleName 0
    $items = New-Object System.Collections.ArrayList
    $procs = @(Get-BedrockProc)
    if ($procs.Count -eq 0) {
        Add-Observation $ModuleName 'Minecraft is not running: loaded-module inspection skipped, files only.'
    }
    foreach ($p in $procs) {
        try {
            foreach ($m in $p.Modules) {
                if ($Only -ne 'All') {
                    $pth = $m.FileName
                    if ($pth.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase) -or (Test-PathLike $pth $script:GameDirs)) { continue }
                }
                [void]$items.Add([pscustomobject]@{ P = $p; Path = $m.FileName; Name = $m.ModuleName })
            }
        } catch { Add-ScanError $ModuleName "PID $($p.Id)" $_.Exception.Message }
    }
    $data = @()
    if ($script:Cfg.Settings.ScanFiles) { $data = @(Get-BedrockDataFiles @('.dll')) }
    $script:Mod.Total = $items.Count + $data.Count
    $rows = New-Object System.Collections.ArrayList

    foreach ($it in $items) {
        if (Step-ScanModule $it.Name) { break }
        try {
            if ($it.P.HasExited) {
                Add-ScanError $ModuleName "PID $($it.P.Id)" 'Minecraft closed during the scan; remaining modules skipped.'
                break
            }
        } catch { }
        try {
            Inspect-Dll -Path $it.Path -Name $it.Name -Loaded $true -Only $Only
            if ($Only -eq 'Signature') {
                $sg = Get-Sig $it.Path
                [void]$rows.Add([pscustomobject]@{ Name = $it.Name; Status = $sg.Status; Signer = $sg.Signer; Path = $it.Path })
            }
        } catch { Add-ScanError $ModuleName $it.Name $_.Exception.Message }
    }
    if (-not $script:Mod.Cancelled) {
        foreach ($f in $data) {
            if (Step-ScanModule $f.Name) { break }
            try { Inspect-Dll -Path $f.FullName -Name $f.Name -Loaded $false -InData $true -Only $Only }
            catch { Add-ScanError $ModuleName $f.Name $_.Exception.Message }
        }
    }
    if ($Only -eq 'Signature') {
        $script:LastRows = @($rows)
        $script:LastCols = @(
            @{ Key = 'Name'; Title = 'Module'; Width = 26 },
            @{ Key = 'Status'; Title = 'Signature'; Width = 12; Color = { param($v) if ($v -eq 'Valid') { 'Green' } elseif ($v -eq 'NotSigned') { 'Yellow' } else { 'Red' } } },
            @{ Key = 'Signer'; Title = 'Publisher'; Width = 24 },
            @{ Key = 'Path'; Title = 'Location'; Width = [Math]::Max(10, $script:W - 4 - 26 - 12 - 24 - 6); PathStyle = $true }
        )
    }
    Stop-ScanModule
}

function Invoke-SignatureScan { Invoke-DllScan -Only 'Signature' -ModuleName 'Digital Signature Scanner' }

function Invoke-HashScan {
    Start-ScanModule 'Hash Scanner' 0
    $items = New-Object System.Collections.ArrayList
    foreach ($p in @(Get-BedrockProc)) {
        try {
            foreach ($m in $p.Modules) {
                $pth = $m.FileName
                if ($pth.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase) -or (Test-PathLike $pth $script:GameDirs)) { continue }
                [void]$items.Add([pscustomobject]@{ Path = $pth; Name = $m.ModuleName; Source = 'Loaded' })
            }
        } catch { Add-ScanError 'Hash Scanner' "PID $($p.Id)" $_.Exception.Message }
    }
    if ($script:Cfg.Settings.ScanFiles) {
        foreach ($f in @(Get-BedrockDataFiles @('.dll', '.lua'))) {
            [void]$items.Add([pscustomobject]@{ Path = $f.FullName; Name = $f.Name; Source = 'GameData' })
        }
    }
    $script:Mod.Total = $items.Count
    $rows = New-Object System.Collections.ArrayList
    foreach ($it in $items) {
        if (Step-ScanModule $it.Name) { break }
        try {
            $sha = Get-Sha $it.Path
            Register-Inspected $it.Path 'File'
            $verdict = 'No match'
            if (-not $sha) { $verdict = 'Unreadable' }
            $kh = Find-KnownHash $sha
            if ($kh) {
                $verdict = 'KNOWN-BAD: ' + $kh.Label
                $ind = New-Object System.Collections.ArrayList
                [void]$ind.Add((New-Indicator 'KnownHash' "SHA-256 matches known-indicator entry: $($kh.Label)."))
                Add-Finding -Name $it.Name -Path $it.Path -Sha $sha -Indicators $ind -Observed @("Source: $($it.Source)")
            } else {
                $sg = Get-Sig $it.Path
                $al = Test-Allowlist -Name $it.Name -Path $it.Path -Sha $sha -Signer $sg.Signer -SigStatus $sg.Status
                if ($al.State -eq 'allowed') { $verdict = 'Allowlisted' }
            }
            [void]$rows.Add([pscustomobject]@{ Name = $it.Name; Sha = $sha; Source = $it.Source; Verdict = $verdict })
        } catch { Add-ScanError 'Hash Scanner' $it.Name $_.Exception.Message }
    }
    $script:LastRows = @($rows)
    $shaW = 64
    if ($script:W -lt 116) { $shaW = 20 }
    $script:LastCols = @(
        @{ Key = 'Name'; Title = 'File'; Width = 20 },
        @{ Key = 'Sha'; Title = 'SHA-256'; Width = $shaW },
        @{ Key = 'Source'; Title = 'Source'; Width = 8 },
        @{ Key = 'Verdict'; Title = 'Result'; Width = 12; Color = { param($v) if ($v -like 'KNOWN-BAD*') { 'Red' } elseif ($v -eq 'Allowlisted') { 'Green' } else { 'Gray' } } }
    )
    Stop-ScanModule
}

function Invoke-LuaScan {
    Start-ScanModule 'Lua Scanner' 0
    $files = @()
    if ($script:Cfg.Settings.ScanFiles) { $files = @(Get-BedrockDataFiles @('.lua')) }
    $extra = New-Object System.Collections.ArrayList
    if ($script:Cfg.Settings.ScanFiles) {
        $d = [int]$script:Cfg.Settings.FileDepth
        foreach ($r in @((Join-Path $env:USERPROFILE 'Downloads'), (Join-Path $env:USERPROFILE 'Desktop'), (Join-Path $env:USERPROFILE 'Documents'))) {
            if (-not (Test-Path -LiteralPath $r)) { continue }
            try {
                foreach ($f in @(Get-ChildItem -LiteralPath $r -Recurse -Depth $d -File -Force -Filter '*.lua' -ErrorAction SilentlyContinue)) {
                    if ($f.Extension.ToLower() -eq '.lua') { [void]$extra.Add($f) }
                }
            } catch { Add-ScanError 'Lua Scanner' $r $_.Exception.Message }
        }
    }
    $script:Mod.Total = $files.Count + $extra.Count
    foreach ($f in $files) {
        if (Step-ScanModule $f.Name) { break }
        try {
            Register-Inspected $f.FullName 'File'
            $sha = Get-Sha $f.FullName
            $head = Read-ScriptHead $f.FullName
            $ind = New-Object System.Collections.ArrayList
            [void]$ind.Add((New-Indicator 'ScriptInGameData' 'A Lua script is stored inside the Bedrock data folder.'))
            $tok = Find-Token ($f.FullName + ' ' + $head.Text)
            if ($tok) { [void]$ind.Add((New-Indicator 'KnownName' "Path or script content references indicator '$($tok.Token)' ($($tok.Desc)).")) }
            $kh = Find-KnownHash $sha
            if ($kh) { [void]$ind.Add((New-Indicator 'KnownHash' "SHA-256 matches known-indicator entry: $($kh.Label).")) }
            $obs = New-Object System.Collections.ArrayList
            foreach ($x in @(Get-FileFacts $f.FullName)) { [void]$obs.Add($x) }
            $i = 0
            foreach ($l in @($head.Lines)) { $i++; [void]$obs.Add("Script line ${i}: $l") }
            Add-Finding -Name $f.Name -Path $f.FullName -Sha $sha -Sig 'n/a (script)' -Indicators $ind -Observed @($obs)
        } catch { Add-ScanError 'Lua Scanner' $f.Name $_.Exception.Message }
    }
    if (-not $script:Mod.Cancelled) {
        foreach ($f in $extra) {
            if (Step-ScanModule $f.Name) { break }
            try {
                Register-Inspected $f.FullName 'File'
                $tok = Find-Token $f.FullName
                if ($tok) {
                    $ind = New-Object System.Collections.ArrayList
                    [void]$ind.Add((New-Indicator 'KnownName' "Path/name matches indicator '$($tok.Token)' ($($tok.Desc))."))
                    Add-Finding -Name $f.Name -Path $f.FullName -Sha (Get-Sha $f.FullName) -Indicators $ind -Observed @(Get-FileFacts $f.FullName)
                } else {
                    Add-Observation 'Lua Scanner' "Lua script outside game folders: $($f.Name)" $f.FullName $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                }
            } catch { Add-ScanError 'Lua Scanner' $f.Name $_.Exception.Message }
        }
    }
    Stop-ScanModule
}

function Invoke-MemoryScan {
    $name = 'Memory Integrity Scanner'
    Start-ScanModule $name 0
    $procs = @(Get-BedrockProc)
    if ($procs.Count -eq 0) {
        Add-Observation $name 'Minecraft is not running: memory inspection skipped.'
        Stop-ScanModule
        return
    }
    if (-not $script:NativeOk) {
        Add-ScanError $name 'native helper' 'The memory inspection helper could not be compiled on this system.'
        Stop-ScanModule
        return
    }
    $probes = New-Object System.Collections.ArrayList
    $plan = New-Object System.Collections.ArrayList
    $rwx = 0
    try {
        foreach ($p in $procs) {
            $probe = New-Object MemProbe
            $rc = $probe.Open($p.Id)
            if ($rc -ne 0) {
                Add-ScanError $name "PID $($p.Id)" "Could not open the process for reading (Win32 error $rc). Run as Administrator."
                continue
            }
            [void]$probes.Add($probe)
            $n = $probe.Collect()
            $rwx += $probe.RwxCount
            for ($i = 0; $i -lt $n; $i++) { [void]$plan.Add([pscustomobject]@{ Probe = $probe; Index = $i; ProcId = $p.Id }) }
        }
        $script:Mod.Total = $plan.Count
        foreach ($w in $plan) {
            if (Step-ScanModule ("PID $($w.ProcId) allocation $($w.Index + 1)/$($plan.Count)")) { break }
            try {
                $hit = $w.Probe.Check($w.Index)
                if ($hit) {
                    $parts = $hit.Split('|')
                    $ind = New-Object System.Collections.ArrayList
                    [void]$ind.Add((New-Indicator 'MappedPE' "An executable allocation at 0x$($parts[1]) starts with a valid PE header but is not backed by a file or listed as a module."))
                    $obs = @("PID: $($w.ProcId)", "Address: 0x$($parts[1])", "First region size: $($parts[2]) bytes", "Region protection flags: 0x$($parts[3])", 'Source: VirtualQueryEx / ReadProcessMemory (read-only)')
                    Add-Finding -Name ("Mapped PE image @0x" + $parts[1]) -Key ("mem|$($w.ProcId)|$($parts[1])") -Indicators $ind -Observed $obs -Sig 'n/a (memory)'
                }
            } catch { Add-ScanError $name "allocation $($w.Index)" $_.Exception.Message }
        }
    } finally {
        foreach ($pr in $probes) { try { $pr.Close() } catch { } }
    }
    if ($rwx -gt 0) {
        Add-Observation $name "Large private read-write-execute regions: $rwx (informational; drivers and runtimes can create these)."
    }
    Stop-ScanModule
}

function Invoke-InjectionScan {
    $name = 'Injection Investigation'
    Start-ScanModule $name 0
    $tokens = @(Get-ScanTokens)
    $work = New-Object System.Collections.ArrayList
    $cut = (Get-Date).AddDays(-14)

    $bam = @()
    if ($script:Cfg.Settings.ScanTraces) {
        try { $bam = @(Get-BamEntries) } catch { Add-ScanError $name 'BAM registry' $_.Exception.Message }
    }
    foreach ($e in $bam) {
        if ($e.Time -ge $cut) { [void]$work.Add([pscustomobject]@{ Type = 'BAM'; Name = $e.Path; Path = $e.Path; Time = $e.Time }) }
    }
    $pfDir = Join-Path $env:SystemRoot 'Prefetch'
    $pf = @()
    $pfOk = $false
    if ($script:Cfg.Settings.ScanTraces) {
        try { $pf = @(Get-ChildItem -LiteralPath $pfDir -Filter '*.pf' -ErrorAction Stop); $pfOk = $true }
        catch { Add-ScanError $name 'Prefetch' $_.Exception.Message }
    }
    foreach ($f in $pf) { [void]$work.Add([pscustomobject]@{ Type = 'Prefetch'; Name = $f.Name; Path = $f.FullName; Time = $f.LastWriteTime }) }
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $pp = ''
        try { $pp = [string]$p.Path } catch { }
        [void]$work.Add([pscustomobject]@{ Type = 'Process'; Name = $p.ProcessName; Path = $pp; Time = [datetime]::MinValue; Pid = $p.Id })
    }
    $script:Mod.Total = $work.Count + 1

    if (Step-ScanModule 'Prefetch health check') { Stop-ScanModule; return }
    if ($pfOk -and $pf.Count -eq 0) {
        $svc = 'unknown'
        try { $svc = [string](Get-Service -Name 'SysMain' -ErrorAction Stop).Status } catch { }
        $ind = New-Object System.Collections.ArrayList
        [void]$ind.Add((New-Indicator 'TraceCleared' 'The Prefetch folder contains no .pf files.'))
        Add-Finding -Name 'Prefetch folder is empty' -Path $pfDir -Key 'trace|prefetch-empty' -Indicators $ind -Sig 'n/a' -Observed @("SysMain service status: $svc", 'Prefetch can be empty if SysMain is disabled or the files were cleared.')
    }

    foreach ($w in $work) {
        if (Step-ScanModule ($w.Type + ': ' + $w.Name)) { break }
        try {
            $tok = $null
            if ($w.Type -eq 'Process') { $tok = Find-Token $w.Name } else { $tok = Find-Token $w.Path }
            if (-not $tok) { continue }
            $ind = New-Object System.Collections.ArrayList
            $leaf = $w.Name
            $obs = New-Object System.Collections.ArrayList
            switch ($w.Type) {
                'BAM' {
                    $leaf = Split-Path -Leaf $w.Path
                    [void]$ind.Add((New-Indicator 'InjectorTrace' "Background Activity Monitor shows an execution matching '$($tok.Token)' ($($tok.Desc))."))
                    [void]$obs.Add("Last execution (BAM): $($w.Time.ToString('yyyy-MM-dd HH:mm:ss'))")
                }
                'Prefetch' {
                    [void]$ind.Add((New-Indicator 'InjectorTrace' "A Prefetch entry matches '$($tok.Token)' ($($tok.Desc))."))
                    [void]$obs.Add("Prefetch last written: $($w.Time.ToString('yyyy-MM-dd HH:mm:ss'))")
                }
                default {
                    [void]$ind.Add((New-Indicator 'InjectorTrace' "A running process name matches '$($tok.Token)' ($($tok.Desc))."))
                    [void]$obs.Add("Process ID: $($w.Pid)")
                }
            }
            $key = ($w.Type + '|' + $w.Path + '|' + $w.Name).ToLower()
            Add-Finding -Name $leaf -Path $w.Path -Key $key -Indicators $ind -Observed @($obs) -Sig 'n/a'
        } catch { Add-ScanError $name $w.Name $_.Exception.Message }
    }
    Stop-ScanModule
}

function Invoke-RecentFileScan {
    $name = 'Recent File Activity'
    Start-ScanModule $name 0
    $days = [int]$script:Cfg.Settings.RecentDays
    $cut = (Get-Date).AddDays(-$days)
    $depth = [int]$script:Cfg.Settings.FileDepth
    $exts = @('.dll', '.lua', '.exe', '.zip', '.rar', '.7z')
    $roots = @(
        (Join-Path $env:USERPROFILE 'Downloads'), (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'Documents'), $env:TEMP, 'C:\Users\Public'
    ) + @(Get-BedrockDataRoots)
    $script:Mod.Total = $roots.Count
    $hits = New-Object System.Collections.ArrayList
    foreach ($r in $roots) {
        if (Step-ScanModule $r) { break }
        if (-not (Test-Path -LiteralPath $r)) { continue }
        try {
            $found = @(Get-ChildItem -LiteralPath $r -Recurse -Depth $depth -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $exts -contains $_.Extension.ToLower() -and ($_.LastWriteTime -ge $cut -or $_.CreationTime -ge $cut) })
            foreach ($f in $found) { [void]$hits.Add($f) }
            $script:Mod.Total += $found.Count
        } catch { Add-ScanError $name $r $_.Exception.Message }
    }
    $rows = New-Object System.Collections.ArrayList
    if (-not $script:Mod.Cancelled) {
        foreach ($f in @($hits | Sort-Object LastWriteTime -Descending)) {
            if (Step-ScanModule $f.Name) { break }
            try {
                Register-Inspected $f.FullName 'File'
                $when = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                Add-Observation $name "Recent $($f.Extension.ToLower()) file: $($f.Name)" $f.FullName $when
                if ($rows.Count -lt 40) {
                    [void]$rows.Add([pscustomobject]@{ When = $when; Name = $f.Name; Type = $f.Extension.ToLower(); Path = $f.FullName })
                }
                $tok = Find-Token $f.FullName
                if ($tok) {
                    $ind = New-Object System.Collections.ArrayList
                    [void]$ind.Add((New-Indicator 'KnownName' "Recent file path/name matches indicator '$($tok.Token)' ($($tok.Desc))."))
                    Add-Finding -Name $f.Name -Path $f.FullName -Sha (Get-Sha $f.FullName) -Indicators $ind -Observed @(Get-FileFacts $f.FullName) -Sig 'n/a'
                }
            } catch { Add-ScanError $name $f.Name $_.Exception.Message }
        }
    }
    $script:LastRows = @($rows)
    $script:LastCols = @(
        @{ Key = 'When'; Title = 'Modified'; Width = 16 },
        @{ Key = 'Type'; Title = 'Type'; Width = 5 },
        @{ Key = 'Name'; Title = 'File'; Width = 28 },
        @{ Key = 'Path'; Title = 'Location'; Width = [Math]::Max(10, $script:W - 4 - 16 - 5 - 28 - 6); PathStyle = $true }
    )
    Stop-ScanModule
}

function Invoke-Correlation {
    $strongKinds = @('MappedPE', 'KnownName', 'KnownHash', 'MissingOnDisk', 'Impostor')
    $strong = @($script:Findings | Where-Object { $f = $_; $f.Key -notlike 'corr|*' -and @($f.Indicators | Where-Object { $strongKinds -contains $_.Kind }).Count -gt 0 -and $f.Class -ne 'CLEAN' })
    $traces = @($script:Findings | Where-Object { $f = $_; @($f.Indicators | Where-Object { $_.Kind -eq 'InjectorTrace' }).Count -gt 0 })
    if ($strong.Count -eq 0 -or $traces.Count -eq 0) { return }
    $ind = New-Object System.Collections.ArrayList
    foreach ($s in $strong) { foreach ($i in $s.Indicators) { if ($strongKinds -contains $i.Kind) { [void]$ind.Add($i) } } }
    [void]$ind.Add($traces[0].Indicators[0])
    $obs = New-Object System.Collections.ArrayList
    foreach ($s in $strong) { [void]$obs.Add("In-game indicator: $($s.Name) ($($s.Detection))") }
    foreach ($t in $traces) { [void]$obs.Add("Execution trace: $($t.Name) [$($t.Key.Split('|')[0])]") }
    Add-Finding -Name 'Correlated injection evidence' -Key 'corr|inject' -Module 'Correlation' -Indicators $ind -Observed @($obs) -Sig 'n/a'
}

# ---------------------------------------------------------------------------
# Results presentation
# ---------------------------------------------------------------------------
function Get-Counts {
    $h = @($script:Findings | Where-Object { $_.Class -eq 'HIGH' }).Count
    $s = @($script:Findings | Where-Object { $_.Class -eq 'SUSPICIOUS' }).Count
    $c = @($script:Findings | Where-Object { $_.Class -eq 'CLEAN' }).Count
    return [pscustomobject]@{ High = $h; Suspicious = $s; Clean = $c }
}

function Show-FindingDetail {
    param($F)
    while ($true) {
        Show-Header ('Finding #' + $F.Id)
        $col = Get-ClassColor $F.Class
        Write-Seg ('  ' + (Get-ClassLabel $F.Class) + '   ' + $F.Detection) $col
        $rv = 'No'; if ($F.Reviewed) { $rv = 'Yes (marked by staff)' }
        Write-Section 'Observed facts'
        $facts = @(
            @('Detection', $F.Detection), @('Name', $F.Name), @('Path', $F.Path), @('SHA-256', $F.Sha256),
            @('Signature', ($F.Signature + $(if ($F.Signer) { ' - ' + $F.Signer }))), @('Detected', $F.Detected),
            @('Found by', ($F.Modules -join ', ')), @('Reviewed', $rv)
        )
        foreach ($p in $facts) {
            $val = [string]$p[1]; if (-not $val) { $val = '-' }
            Write-Seg ('  ' + ([string]$p[0]).PadRight(11)) 'DarkGray' -NoNewline
            Write-Seg (Format-Cut $val ($script:W - 16)) 'White'
        }
        foreach ($o in $F.Observed) { Write-Seg ('  ' + $script:G.Info + ' ' + (Format-Cut $o ($script:W - 6))) 'Gray' }
        Write-Section 'Indicators'
        foreach ($i in $F.Indicators) {
            Write-Seg ('  ' + $script:G.Warn + ' ') 'Yellow' -NoNewline
            Write-Seg ($script:KindTitle[$i.Kind] + ': ') 'White' -NoNewline
            Write-Seg (Format-Cut $i.Text ($script:W - 8 - $script:KindTitle[$i.Kind].Length)) 'Gray'
        }
        Write-Section 'Automated interpretation'
        $conf = 'Informational'; if ($F.Class -eq 'HIGH') { $conf = 'High (multiple independent indicators or known-bad hash)' }
        if ($F.Class -eq 'SUSPICIOUS') { $conf = 'Needs manual review' }
        Write-Seg ('  Confidence: ' + $conf + '   Score: ' + $F.Score) $col
        $words = $F.Explanation -split ' '
        $line = '  '
        foreach ($wd in $words) {
            if (($line.Length + $wd.Length + 1) -gt ($script:W - 4)) { Write-Seg $line 'Gray'; $line = '  ' }
            $line += $wd + ' '
        }
        if ($line.Trim()) { Write-Seg $line 'Gray' }
        Write-Section 'Recommended investigation steps'
        $n = 0
        foreach ($st in $F.Steps) { $n++; Write-Seg ('  ' + $n + '. ' + (Format-Cut $st ($script:W - 8))) 'Gray' }
        Write-Host ''
        Write-Seg '  [R] mark reviewed   [A] allowlist hash   [C] copy to clipboard   [B] back' 'Cyan'
        $a = (Read-Choice 'Action').ToUpper()
        switch ($a) {
            'R' {
                $key = Get-ReviewKey $F
                if (@($script:Cfg.Reviewed) -notcontains $key) { $script:Cfg.Reviewed = @($script:Cfg.Reviewed) + $key; [void](Export-Config) }
                Update-Finding $F
            }
            'A' {
                if (-not $F.Sha256) { Write-Status warn 'This finding has no file hash to allowlist.'; Start-Sleep -Milliseconds 1200 }
                else {
                    $ok = Read-Choice 'Allowlist this exact SHA-256 as legitimate? (Y/N)'
                    if ($ok -match '^[Yy]') {
                        $script:Cfg.Allow = @($script:Cfg.Allow) + [pscustomobject]@{ Type = 'Hash'; Value = $F.Sha256; Hash = $F.Sha256; Note = ('Added by staff for ' + $F.Name) }
                        [void](Export-Config)
                        Write-Status ok 'Added to the allowlist. It will be skipped in future scans.'
                        Start-Sleep -Milliseconds 1200
                    }
                }
            }
            'C' {
                $txt = "[{0}] {1}`r`nName: {2}`r`nPath: {3}`r`nSHA-256: {4}`r`nSignature: {5}`r`nIndicators: {6}`r`n{7}" -f (Get-ClassLabel $F.Class), $F.Detection, $F.Name, $F.Path, $F.Sha256, $F.Signature, (($F.Indicators | ForEach-Object { $_.Text }) -join ' | '), $F.Explanation
                try { Set-Clipboard -Value $txt; Write-Status ok 'Copied.' } catch { Write-Status warn 'Clipboard is not available in this session.' }
                Start-Sleep -Milliseconds 900
            }
            'B' { return }
            '' { return }
        }
    }
}

function Show-ScanResults {
    param([string]$Title)
    $runMods = @($script:ModResults | Select-Object -Skip $script:RunStart)
    $runNames = @($runMods | ForEach-Object { $_.Name }) + @('Correlation')
    $all = @($script:Findings | Where-Object { $f = $_; @($f.Modules | Where-Object { $runNames -contains $_ }).Count -gt 0 })
    $bad = @($all | Where-Object { $_.Class -ne 'CLEAN' } | Sort-Object @{ Expression = { if ($_.Class -eq 'HIGH') { 0 } else { 1 } } }, Id)
    $nHigh = @($bad | Where-Object { $_.Class -eq 'HIGH' }).Count
    $nSus = @($bad | Where-Object { $_.Class -eq 'SUSPICIOUS' }).Count
    $cancelled = @($runMods | Where-Object { $_.Status -eq 'Cancelled' }).Count -gt 0

    while ($true) {
        Show-Header ($Title + ' - Results')
        if ($nHigh -gt 0) { Write-Seg ("  $($script:G.Bad) HIGH CONFIDENCE: $nHigh finding(s) with multiple independent indicators" + $(if ($nSus) { ", plus $nSus suspicious" })) 'Red' }
        elseif ($nSus -gt 0) { Write-Seg "  $($script:G.Warn) SUSPICIOUS: $nSus anomaly(ies) need manual investigation (not proof of cheating)" 'Yellow' }
        else { Write-Seg "  $($script:G.Ok) CLEAN: no suspicious indicators found within the inspected scope" 'Green' }
        if ($cancelled) { Write-Status warn 'The scan was cancelled, so these results are partial.' }

        Write-Section 'Modules'
        $mrows = @($runMods | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Items = [string]$_.Items; Found = [string]$_.Findings; Allow = [string]$_.Allowlisted; Err = [string]$_.Errors; Time = ([string]$_.Seconds + 's'); Status = $_.Status }
        })
        Write-Table $mrows @(
            @{ Key = 'Name'; Title = 'Module'; Width = 28 },
            @{ Key = 'Items'; Title = 'Items'; Width = 7 },
            @{ Key = 'Found'; Title = 'Findings'; Width = 8; Color = { param($v) if ($v -ne '0') { 'Yellow' } else { 'Green' } } },
            @{ Key = 'Allow'; Title = 'Allowed'; Width = 8 },
            @{ Key = 'Err'; Title = 'Errors'; Width = 7; Color = { param($v) if ($v -ne '0') { 'Yellow' } else { 'Gray' } } },
            @{ Key = 'Time'; Title = 'Time'; Width = 8 },
            @{ Key = 'Status'; Title = 'Status'; Width = 10; Color = { param($v) if ($v -eq 'Completed') { 'Green' } else { 'Yellow' } } }
        )

        if (@($script:LastRows).Count -gt 0 -and @($script:LastCols).Count -gt 0) {
            Write-Section 'Details'
            Write-Table $script:LastRows $script:LastCols
        }

        $runErrs = @($script:Errors | Select-Object -Skip $script:RunErrStart)
        if ($runErrs.Count -gt 0) {
            Write-Section 'Errors and warnings'
            $acc = @($runErrs | Where-Object { $_.Kind -eq 'AccessDenied' }).Count
            if ($acc -gt 0) { Write-Status warn "$acc access-denied item(s). Running as Administrator reduces these." }
            foreach ($e in @($runErrs | Select-Object -First 6)) {
                Write-Seg ('  ' + $script:G.Warn + ' ' + (Format-Cut ($e.Module + ' / ' + $e.Target + ': ' + $e.Message) ($script:W - 6))) 'Yellow'
            }
            if ($runErrs.Count -gt 6) { Write-Seg ("  ... and $($runErrs.Count - 6) more (saved in the report)") 'DarkGray' }
        }

        if ($bad.Count -gt 0) {
            Write-Section 'Findings'
            $frows = @($bad | ForEach-Object {
                $mark = [string]$_.Id; if ($_.Reviewed) { $mark += 'r' }
                $loc = $_.Path; if (-not $loc) { $loc = $_.Key }
                [pscustomobject]@{ Id = $mark; Class = (Get-ClassLabel $_.Class $true); Det = $_.Detection; Name = $_.Name; Sha = (Format-ShaShort $_.Sha256); Sig = $_.Signature; Loc = $loc }
            })
            $fixed = 4 + 9 + 24 + 20 + 14 + 10
            $locW = $script:W - 4 - $fixed - (2 * 6)
            $cols = @(
                @{ Key = 'Id'; Title = '#'; Width = 4 },
                @{ Key = 'Class'; Title = 'Class'; Width = 9; Color = { param($v) if ($v -like 'HIGH*') { 'Red' } else { 'Yellow' } } },
                @{ Key = 'Det'; Title = 'Detection'; Width = 24 },
                @{ Key = 'Name'; Title = 'File / process'; Width = 20 },
                @{ Key = 'Sha'; Title = 'SHA-256'; Width = 14 },
                @{ Key = 'Sig'; Title = 'Signature'; Width = 10 }
            )
            if ($locW -ge 10) { $cols += @{ Key = 'Loc'; Title = 'Location'; Width = $locW; PathStyle = $true } }
            Write-Table $frows $cols
            Write-Host ''
            $pick = Read-Choice 'Enter a finding # for full details, or press Enter to go back'
            if (-not $pick) { return }
            $num = 0
            if ([int]::TryParse(($pick -replace 'r', ''), [ref]$num)) {
                $f = $bad | Where-Object { $_.Id -eq $num } | Select-Object -First 1
                if ($f) { Show-FindingDetail $f; continue }
            }
            Write-Status warn 'That is not a listed finding number.'
            Start-Sleep -Milliseconds 900
        } else {
            Write-Host ''
            Write-Seg '  A clean result is not proof. See Evidence Reports for the stated limitations.' 'DarkGray'
            Wait-Enter 'Press Enter to return to the menu'
            return
        }
    }
}

function Invoke-ScanAction {
    param([string]$Title, [scriptblock]$Body)
    if ($script:Busy) { Write-Status warn 'A scan is already running.'; return }
    $script:Busy = $true
    try {
        Show-Header $Title
        $script:CancelAll = $false
        $script:RunStart = $script:ModResults.Count
        $script:RunErrStart = $script:Errors.Count
        $script:LastRows = @(); $script:LastCols = @()
        try { & $Body }
        catch {
            Write-Status bad ("The scan stopped unexpectedly: " + $_.Exception.Message)
            Write-Log 'ERROR' ("Scan aborted: " + $_.Exception.Message)
            if ($script:Mod) { $script:Mod = $null }
        }
        $script:LastScan = Get-Date
        Show-ScanResults $Title
    } finally { $script:Busy = $false }
}

function Invoke-FullScan {
    $script:Findings.Clear(); $script:Observations.Clear(); $script:Errors.Clear(); $script:ModResults.Clear()
    $script:NextId = 1
    $script:RunStart = 0
    $script:RunErrStart = 0
    $s = $script:Cfg.Settings
    Invoke-DllScan
    if (-not $script:CancelAll) { Invoke-SignatureScan }
    if (-not $script:CancelAll) { Invoke-HashScan }
    if (-not $script:CancelAll -and $s.ScanFiles) { Invoke-LuaScan }
    if (-not $script:CancelAll -and $s.ScanMemory) { Invoke-MemoryScan }
    if (-not $script:CancelAll -and $s.ScanTraces) { Invoke-InjectionScan }
    if (-not $script:CancelAll -and $s.ScanFiles) { Invoke-RecentFileScan }
    Invoke-Correlation
    $script:LastRows = @(); $script:LastCols = @()
    try {
        $base = Save-Report
        Write-Host ''
        Write-Status ok ('Evidence saved: ' + $base + '.json / .txt')
    } catch { Write-Status warn ('Report could not be saved: ' + $_.Exception.Message) }
}

# ---------------------------------------------------------------------------
# Process inspector
# ---------------------------------------------------------------------------
function Show-ProcessInspector {
    Show-Header 'Minecraft Process Inspector'
    $procs = @(Get-BedrockProc)
    if ($procs.Count -eq 0) {
        Write-Status warn 'Minecraft.Windows.exe is not running. Open Bedrock and join a world, then try again.'
        Wait-Enter
        return
    }
    foreach ($p in $procs) {
        try { $p.Refresh() } catch { }
        $path = ''; try { $path = [string]$p.Path } catch { $path = '(access denied)' }
        $start = ''; $up = ''
        try { $start = $p.StartTime.ToString('yyyy-MM-dd HH:mm:ss'); $up = ((Get-Date) - $p.StartTime).ToString('hh\:mm\:ss') } catch { $start = '(unavailable)' }
        $mods = @(); $modErr = ''
        try { $mods = @($p.Modules) } catch { $modErr = $_.Exception.Message }
        $sys = 0; $game = 0; $other = 0
        foreach ($m in $mods) {
            if ($m.FileName.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)) { $sys++ }
            elseif (Test-PathLike $m.FileName $script:GameDirs) { $game++ }
            else { $other++ }
        }
        $sig = ''
        if ($path -and (Test-Path -LiteralPath $path)) { $g = Get-Sig $path; $sig = $g.Status; if ($g.Signer) { $sig += ' - ' + $g.Signer } }
        $ver = Get-McVersion; if (-not $ver) { $ver = '(unavailable)' }
        Write-Section ('Process ' + $p.Id)
        $rows = @(
            @('Process ID', [string]$p.Id), @('Executable', $path), @('Executable signature', $sig), @('Package version', $ver),
            @('Started', $start), @('Uptime', $up), @('Memory (working set)', ([string][Math]::Round($p.WorkingSet64 / 1MB, 0) + ' MB')),
            @('Threads / handles', ([string]$p.Threads.Count + ' / ' + [string]$p.HandleCount)),
            @('Responding', [string]$p.Responding)
        )
        foreach ($r in $rows) {
            Write-Seg ('  ' + $r[0].PadRight(22)) 'DarkGray' -NoNewline
            Write-Seg (Format-PathCut $r[1] ($script:W - 28)) 'White'
        }
        if ($modErr) { Write-Status warn ('Modules unreadable: ' + $modErr) }
        else {
            Write-Seg ('  ' + 'Loaded modules'.PadRight(22)) 'DarkGray' -NoNewline
            Write-Seg ("$($mods.Count) total: $sys Windows, $game Minecraft, $other other (inspect these with the DLL Scanner)") 'White'
        }
    }
    Wait-Enter
}

# ---------------------------------------------------------------------------
# Evidence reports
# ---------------------------------------------------------------------------
function New-ReportObject {
    $c = Get-Counts
    $isAdmin = Test-IsAdmin
    $procs = @(Get-BedrockProc)
    $os = ''; try { $os = [string](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { }
    $fnd = @($script:Findings | ForEach-Object {
        $fi = $_
        [pscustomobject]@{
            Id = $fi.Id; Key = $fi.Key; Class = $fi.Class; Score = $fi.Score; Detection = $fi.Detection; Name = $fi.Name
            Path = $fi.Path; Sha256 = $fi.Sha256; Signature = $fi.Signature; Signer = $fi.Signer; Detected = $fi.Detected
            Modules = @($fi.Modules)
            Indicators = @($fi.Indicators | ForEach-Object { [pscustomobject]@{ Kind = $_.Kind; Text = $_.Text; Weight = $_.Weight } })
            ObservedFacts = @($fi.Observed); AutomatedInterpretation = $fi.Explanation; RecommendedSteps = @($fi.Steps); Reviewed = $fi.Reviewed
        }
    })
    $scope = @(
        'Loaded modules of Minecraft.Windows.exe (path, signature, hash, allowlist, indicator database)',
        'DLL and Lua files inside the Bedrock data folders (RoamingState, LocalState)',
        'Executable memory allocations of Minecraft.Windows.exe (read-only PE header check)',
        'Execution traces (BAM, Prefetch, running process names) matched against the indicator database',
        ('Recent .dll/.lua/.exe/.zip/.rar/.7z files in Downloads, Desktop, Documents, Temp, Public, Bedrock data (last ' + $script:Cfg.Settings.RecentDays + ' days)'),
        'Not collected: passwords, browser data, cookies, documents, or any personal file contents'
    )
    $lim = @(
        'Manually mapped code with an erased PE header may not be detected.',
        'Kernel-mode, hypervisor-based or hardware cheats are outside the scope of a user-mode scan.',
        'Name-based indicators only match what is in the known-indicator database.',
        'Unsigned, unfamiliar or oddly named files are never treated as malicious on their own.',
        'A clean result is not proof that no cheat was used.'
    )
    [pscustomobject]@{
        Tool = 'BEDROCK SS'; Version = $script:Version; IndicatorDatabase = $script:DbVersion; Publisher = $script:Publisher
        Generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Machine = $env:COMPUTERNAME; WindowsUser = $env:USERNAME
        OperatingSystem = $os; RanAsAdministrator = $isAdmin; MinecraftRunning = ($procs.Count -gt 0); MinecraftPackageVersion = (Get-McVersion)
        Summary = [pscustomobject]@{ HighConfidence = $c.High; Suspicious = $c.Suspicious; CleanObservations = $c.Clean
            FilesInspected = $script:SeenFiles.Count; ModulesInspected = $script:SeenModules.Count }
        Scope = $scope
        Modules = @($script:ModResults)
        Findings = $fnd
        Observations = @($script:Observations)
        Errors = @($script:Errors)
        Limitations = $lim
        Log = @($script:Log | Where-Object { $_.Level -ne 'DEBUG' -or $script:Cfg.Settings.LogLevel -eq 'Verbose' })
    }
}

function ConvertTo-ReportText {
    param($R)
    $t = New-Object System.Collections.ArrayList
    $bar = ('=' * 78)
    [void]$t.Add($bar); [void]$t.Add(' BEDROCK SS - EVIDENCE REPORT'); [void]$t.Add($bar)
    [void]$t.Add("Tool version : $($R.Version)   Indicator DB: $($R.IndicatorDatabase)   Publisher: $($R.Publisher)")
    [void]$t.Add("Generated    : $($R.Generated)")
    [void]$t.Add("Machine/User : $($R.Machine) / $($R.WindowsUser)   Administrator: $($R.RanAsAdministrator)")
    [void]$t.Add("Windows      : $($R.OperatingSystem)")
    [void]$t.Add("Minecraft    : running=$($R.MinecraftRunning)   package version=$($R.MinecraftPackageVersion)")
    [void]$t.Add('')
    [void]$t.Add('SCOPE (what was inspected)')
    foreach ($s in $R.Scope) { [void]$t.Add("  - $s") }
    [void]$t.Add('')
    [void]$t.Add('SUMMARY')
    [void]$t.Add("  High confidence: $($R.Summary.HighConfidence)   Suspicious: $($R.Summary.Suspicious)   Clean observations: $($R.Summary.CleanObservations)")
    [void]$t.Add("  Files inspected: $($R.Summary.FilesInspected)   Modules inspected: $($R.Summary.ModulesInspected)")
    [void]$t.Add('')
    [void]$t.Add('MODULES')
    foreach ($m in $R.Modules) {
        [void]$t.Add(('  {0,-28} items={1,-5} findings={2,-3} errors={3,-3} {4,6}s  {5}' -f $m.Name, $m.Items, $m.Findings, $m.Errors, $m.Seconds, $m.Status))
    }
    [void]$t.Add('')
    [void]$t.Add($bar); [void]$t.Add(' FINDINGS   (observed facts are separated from automated interpretation)'); [void]$t.Add($bar)
    $shown = @($R.Findings | Where-Object { $_.Class -ne 'CLEAN' })
    if ($shown.Count -eq 0) { [void]$t.Add('No suspicious indicators were found within the inspected scope.') }
    foreach ($f in $shown) {
        [void]$t.Add('')
        [void]$t.Add("[$($f.Class)] #$($f.Id) $($f.Detection)")
        [void]$t.Add('  OBSERVED FACTS')
        [void]$t.Add("    Name      : $($f.Name)")
        [void]$t.Add("    Path      : $($f.Path)")
        [void]$t.Add("    SHA-256   : $($f.Sha256)")
        [void]$t.Add("    Signature : $($f.Signature) $($f.Signer)")
        [void]$t.Add("    Detected  : $($f.Detected)   Found by: $(@($f.Modules) -join ', ')   Reviewed: $($f.Reviewed)")
        foreach ($o in @($f.ObservedFacts)) { [void]$t.Add("    $o") }
        [void]$t.Add('  INDICATORS')
        foreach ($i in @($f.Indicators)) { [void]$t.Add("    - $($i.Kind) (weight $($i.Weight)): $($i.Text)") }
        [void]$t.Add('  AUTOMATED INTERPRETATION')
        [void]$t.Add("    $($f.AutomatedInterpretation)   (score $($f.Score))")
        [void]$t.Add('  RECOMMENDED STEPS')
        foreach ($s in @($f.RecommendedSteps)) { [void]$t.Add("    - $s") }
    }
    [void]$t.Add('')
    [void]$t.Add('OBSERVATIONS (informational, not findings)')
    foreach ($o in @($R.Observations | Select-Object -First 80)) { [void]$t.Add("  - [$($o.Module)] $($o.Text) $($o.Path)") }
    [void]$t.Add('')
    [void]$t.Add('ERRORS AND WARNINGS')
    if (@($R.Errors).Count -eq 0) { [void]$t.Add('  none') }
    foreach ($e in @($R.Errors)) { [void]$t.Add("  - $($e.Time) [$($e.Kind)] $($e.Module) / $($e.Target): $($e.Message)") }
    [void]$t.Add('')
    [void]$t.Add('LIMITATIONS')
    foreach ($l in $R.Limitations) { [void]$t.Add("  - $l") }
    [void]$t.Add('')
    [void]$t.Add('ACTIVITY LOG')
    foreach ($l in @($R.Log)) { [void]$t.Add("  $($l.Time) $($l.Level.PadRight(5)) $($l.Message)") }
    return @($t)
}

function Save-Report {
    $dir = $script:Cfg.Settings.ReportDir
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $base = Join-Path $dir ('BedrockSS_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $obj = New-ReportObject
    $obj | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath ($base + '.json') -Encoding UTF8
    (ConvertTo-ReportText $obj) | Set-Content -LiteralPath ($base + '.txt') -Encoding UTF8
    Write-Log 'INFO' "Report saved: $base"
    return $base
}

function Get-ReportFiles {
    $dir = $script:Cfg.Settings.ReportDir
    if (-not (Test-Path -LiteralPath $dir)) { return @() }
    return @(Get-ChildItem -LiteralPath $dir -Filter 'BedrockSS_*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
}

function Show-ReportList {
    param($Files)
    $rows = @(); $i = 0
    foreach ($f in $Files) {
        $i++
        $sum = ''
        try { $j = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json; $sum = "high $($j.Summary.HighConfidence) / suspicious $($j.Summary.Suspicious)" } catch { $sum = '(unreadable)' }
        $rows += [pscustomobject]@{ N = [string]$i; When = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); Name = $f.Name; Sum = $sum }
    }
    Write-Table $rows @(
        @{ Key = 'N'; Title = '#'; Width = 3 }, @{ Key = 'When'; Title = 'Saved'; Width = 19 },
        @{ Key = 'Name'; Title = 'Report'; Width = 30 }, @{ Key = 'Sum'; Title = 'Summary'; Width = 36 }
    )
}

function Show-ReportViewer {
    param($File)
    $txt = [IO.Path]::ChangeExtension($File.FullName, '.txt')
    if (-not (Test-Path -LiteralPath $txt)) { Write-Status warn 'The readable .txt for this report is missing.'; Wait-Enter; return }
    $lines = @(Get-Content -LiteralPath $txt -Encoding UTF8)
    $page = 24
    try { $page = [Math]::Max(10, $Host.UI.RawUI.WindowSize.Height - 5) } catch { }
    $i = 0
    Show-Header ('Report ' + $File.Name)
    while ($i -lt $lines.Count) {
        $end = [Math]::Min($i + $page, $lines.Count)
        for ($k = $i; $k -lt $end; $k++) {
            $l = $lines[$k]
            $c = 'Gray'
            if ($l -match '^\[HIGH') { $c = 'Red' } elseif ($l -match '^\[SUSPICIOUS') { $c = 'Yellow' } elseif ($l -match '^=|^[A-Z][A-Z /()-]+$') { $c = 'Cyan' }
            Write-Seg (Format-Cut $l ($script:W - 2)) $c
        }
        $i = $end
        if ($i -lt $lines.Count) {
            $a = Read-Choice 'Enter = next page, Q = stop'
            if ($a -match '^[Qq]') { return }
        }
    }
    Wait-Enter
}

function Compare-Reports {
    param($A, $B)
    $ja = Get-Content -LiteralPath $A.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    $jb = Get-Content -LiteralPath $B.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    $fa = @($ja.Findings | Where-Object { $_.Class -ne 'CLEAN' })
    $fb = @($jb.Findings | Where-Object { $_.Class -ne 'CLEAN' })
    $ka = @($fa | ForEach-Object { $_.Key }); $kb = @($fb | ForEach-Object { $_.Key })
    $rows = @()
    foreach ($f in $fb) {
        if ($ka -notcontains $f.Key) { $rows += [pscustomobject]@{ Change = 'NEW'; Class = $f.Class; Name = $f.Name; Detail = $f.Detection } }
        else {
            $old = $fa | Where-Object { $_.Key -eq $f.Key } | Select-Object -First 1
            if ($old.Class -ne $f.Class) { $rows += [pscustomobject]@{ Change = 'CHANGED'; Class = ($old.Class + ' > ' + $f.Class); Name = $f.Name; Detail = $f.Detection } }
        }
    }
    foreach ($f in $fa) { if ($kb -notcontains $f.Key) { $rows += [pscustomobject]@{ Change = 'GONE'; Class = $f.Class; Name = $f.Name; Detail = $f.Detection } } }
    Show-Header 'Compare scans'
    Write-Seg ("  A (older): $($A.Name)   $($ja.Generated)   high $($ja.Summary.HighConfidence) / suspicious $($ja.Summary.Suspicious)") 'Gray'
    Write-Seg ("  B (newer): $($B.Name)   $($jb.Generated)   high $($jb.Summary.HighConfidence) / suspicious $($jb.Summary.Suspicious)") 'Gray'
    Write-Host ''
    if ($rows.Count -eq 0) { Write-Status ok 'No differences in non-clean findings between the two scans.' }
    else {
        Write-Table $rows @(
            @{ Key = 'Change'; Title = 'Change'; Width = 8; Color = { param($v) if ($v -eq 'NEW') { 'Red' } elseif ($v -eq 'GONE') { 'Green' } else { 'Yellow' } } },
            @{ Key = 'Class'; Title = 'Class'; Width = 22 }, @{ Key = 'Name'; Title = 'File / process'; Width = 30 }, @{ Key = 'Detail'; Title = 'Detection'; Width = 34 }
        )
    }
    Wait-Enter
}

function Show-ReportsMenu {
    while ($true) {
        Show-Header 'Evidence Reports'
        Write-Seg ('  Report folder: ' + $script:Cfg.Settings.ReportDir) 'DarkGray'
        Write-Host ''
        Write-Seg '  [1] View a saved report' 'White'
        Write-Seg '  [2] Compare two saved reports' 'White'
        Write-Seg '  [3] Save the current session as a report now' 'White'
        Write-Seg '  [4] Clear current session results' 'White'
        Write-Seg '  [5] Back' 'White'
        Write-Host ''
        $c = Read-Choice 'Select (1-5)'
        switch ($c) {
            '1' {
                $files = @(Get-ReportFiles)
                if ($files.Count -eq 0) { Write-Status warn 'No saved reports yet. Run a Full System Scan first.'; Wait-Enter; continue }
                Write-Host ''; Show-ReportList $files
                $n = Read-Choice 'Report number (Enter to cancel)'
                $idx = 0
                if ([int]::TryParse($n, [ref]$idx) -and $idx -ge 1 -and $idx -le $files.Count) { Show-ReportViewer $files[$idx - 1] }
            }
            '2' {
                $files = @(Get-ReportFiles)
                if ($files.Count -lt 2) { Write-Status warn 'You need at least two saved reports to compare.'; Wait-Enter; continue }
                Write-Host ''; Show-ReportList $files
                $a = Read-Choice 'OLDER report number'; $b = Read-Choice 'NEWER report number'
                $ia = 0; $ib = 0
                if ([int]::TryParse($a, [ref]$ia) -and [int]::TryParse($b, [ref]$ib) -and $ia -ge 1 -and $ib -ge 1 -and $ia -le $files.Count -and $ib -le $files.Count -and $ia -ne $ib) {
                    try { Compare-Reports $files[$ia - 1] $files[$ib - 1] } catch { Write-Status bad ('Could not compare: ' + $_.Exception.Message); Wait-Enter }
                } else { Write-Status warn 'Invalid selection.'; Start-Sleep -Milliseconds 900 }
            }
            '3' {
                if ($script:ModResults.Count -eq 0) { Write-Status warn 'There are no results in this session yet.'; Wait-Enter; continue }
                try { $b = Save-Report; Write-Status ok ('Saved: ' + $b + '.json / .txt') } catch { Write-Status bad ('Could not save: ' + $_.Exception.Message) }
                Wait-Enter
            }
            '4' {
                $script:Findings.Clear(); $script:Observations.Clear(); $script:Errors.Clear(); $script:ModResults.Clear()
                $script:NextId = 1; $script:LastScan = $null
                Write-Status ok 'Session results cleared.'; Start-Sleep -Milliseconds 900
            }
            '5' { return }
            default { Write-Status warn 'Please enter a number from 1 to 5.'; Start-Sleep -Milliseconds 900 }
        }
    }
}

# ---------------------------------------------------------------------------
# Allowlist management
# ---------------------------------------------------------------------------
function Show-AllowlistMenu {
    $page = 0; $size = 14
    while ($true) {
        Show-Header 'Allowlist Management'
        $entries = @($script:Cfg.Allow)
        $pages = [Math]::Max(1, [int][Math]::Ceiling($entries.Count / $size))
        if ($page -ge $pages) { $page = $pages - 1 }
        $slice = @($entries | Select-Object -Skip ($page * $size) -First $size)
        $rows = @(); $i = $page * $size
        foreach ($e in $slice) {
            $i++
            $hs = ''; if ($e.Hash) { $hs = $e.Hash.Substring(0, [Math]::Min(12, $e.Hash.Length)) + '..' }
            $rows += [pscustomobject]@{ N = [string]$i; Type = $e.Type; Value = $e.Value; Hash = $hs; Note = $e.Note }
        }
        Write-Seg "  Allowlisted entries: $($entries.Count)   (page $($page + 1)/$pages)" 'DarkGray'
        Write-Seg '  Allowlisted items are skipped by the scanners, so only add software you have verified.' 'DarkGray'
        Write-Host ''
        Write-Table $rows @(
            @{ Key = 'N'; Title = '#'; Width = 3 }, @{ Key = 'Type'; Title = 'Type'; Width = 7 }, @{ Key = 'Value'; Title = 'Value'; Width = 24 },
            @{ Key = 'Hash'; Title = 'SHA-256'; Width = 14 }, @{ Key = 'Note'; Title = 'Note'; Width = [Math]::Max(10, $script:W - 4 - 3 - 7 - 24 - 14 - 10) }
        )
        Write-Host ''
        Write-Seg '  [A] add   [R] remove   [N] next page   [P] previous page   [B] back' 'Cyan'
        $c = (Read-Choice 'Select').ToUpper()
        switch ($c) {
            'N' { if ($page -lt $pages - 1) { $page++ } }
            'P' { if ($page -gt 0) { $page-- } }
            'B' { return }
            '' { return }
            'R' {
                $n = Read-Choice 'Entry number to remove'
                $idx = 0
                if ([int]::TryParse($n, [ref]$idx) -and $idx -ge 1 -and $idx -le $entries.Count) {
                    $script:Cfg.Allow = @($entries | Where-Object { $_ -ne $entries[$idx - 1] })
                    [void](Export-Config)
                } else { Write-Status warn 'No such entry.'; Start-Sleep -Milliseconds 900 }
            }
            'A' {
                Write-Seg '  Types: 1 Signer (valid signature publisher)  2 Name (file name part)  3 Hash (SHA-256)  4 Path (folder prefix)  5 Client (main DLL by name, optional hash)' 'Gray'
                $t = Read-Choice 'Type (1-5)'
                $type = @{ '1' = 'Signer'; '2' = 'Name'; '3' = 'Hash'; '4' = 'Path'; '5' = 'Client' }[$t]
                if (-not $type) { Write-Status warn 'Invalid type.'; Start-Sleep -Milliseconds 900; continue }
                $val = ''; $hash = ''
                if ($type -eq 'Hash') {
                    $hash = (Read-Choice 'SHA-256 (64 hex characters)').ToLower()
                    if ($hash -notmatch '^[0-9a-f]{64}$') { Write-Status warn 'That is not a valid SHA-256.'; Start-Sleep -Milliseconds 1200; continue }
                    $val = $hash
                } else {
                    $val = Read-Choice 'Value'
                    if (-not $val) { continue }
                    if ($type -eq 'Client') {
                        $hash = (Read-Choice 'Official SHA-256 of this client DLL (Enter to skip)').ToLower()
                        if ($hash -and $hash -notmatch '^[0-9a-f]{64}$') { Write-Status warn 'Invalid SHA-256, entry not added.'; Start-Sleep -Milliseconds 1200; continue }
                    }
                }
                $note = Read-Choice 'Note (what is this software?)'
                $script:Cfg.Allow = @($script:Cfg.Allow) + [pscustomobject]@{ Type = $type; Value = $val; Hash = $hash; Note = $note }
                [void](Export-Config)
            }
            default { Write-Status warn 'Unknown option.'; Start-Sleep -Milliseconds 700 }
        }
    }
}

# ---------------------------------------------------------------------------
# Settings + indicator database
# ---------------------------------------------------------------------------
function Show-IndicatorMenu {
    while ($true) {
        Show-Header 'Known indicator database'
        Write-Seg ("  Database version $($script:DbVersion). Indicators are leads for review, never a verdict on their own.") 'DarkGray'
        Write-Section 'Name indicators'
        $i = 0
        foreach ($t in @($script:Cfg.Tokens)) { $i++; Write-Seg ("  [{0}] {1,-14} {2}" -f $i, $t.Token, $t.Desc) 'Gray' }
        Write-Section 'Known-bad SHA-256 hashes'
        $j = 0
        if (@($script:Cfg.Hashes).Count -eq 0) { Write-Seg '  (none registered)' 'DarkGray' }
        foreach ($h in @($script:Cfg.Hashes)) { $j++; Write-Seg ("  [{0}] {1}  {2}" -f $j, $h.Sha256, $h.Label) 'Gray' }
        Write-Host ''
        Write-Seg '  [1] add name   [2] remove name   [3] add hash   [4] remove hash   [B] back' 'Cyan'
        $c = (Read-Choice 'Select').ToUpper()
        switch ($c) {
            '1' {
                $tok = (Read-Choice 'Name fragment (use something specific, e.g. a client name)').ToLower()
                if ($tok.Length -lt 4) { Write-Status warn 'Use at least 4 characters to avoid false positives.'; Start-Sleep -Milliseconds 1300; continue }
                $d = Read-Choice 'Description'
                $script:Cfg.Tokens = @($script:Cfg.Tokens) + [pscustomobject]@{ Token = $tok; Desc = $d }; [void](Export-Config)
            }
            '2' {
                $n = Read-Choice 'Number to remove'; $idx = 0; $all = @($script:Cfg.Tokens)
                if ([int]::TryParse($n, [ref]$idx) -and $idx -ge 1 -and $idx -le $all.Count) { $script:Cfg.Tokens = @($all | Where-Object { $_ -ne $all[$idx - 1] }); [void](Export-Config) }
            }
            '3' {
                $hash = (Read-Choice 'SHA-256 (64 hex characters)').ToLower()
                if ($hash -notmatch '^[0-9a-f]{64}$') { Write-Status warn 'That is not a valid SHA-256.'; Start-Sleep -Milliseconds 1200; continue }
                $lab = Read-Choice 'Label (what is this file?)'
                $script:Cfg.Hashes = @($script:Cfg.Hashes) + [pscustomobject]@{ Sha256 = $hash; Label = $lab }; [void](Export-Config)
            }
            '4' {
                $n = Read-Choice 'Number to remove'; $idx = 0; $all = @($script:Cfg.Hashes)
                if ([int]::TryParse($n, [ref]$idx) -and $idx -ge 1 -and $idx -le $all.Count) { $script:Cfg.Hashes = @($all | Where-Object { $_ -ne $all[$idx - 1] }); [void](Export-Config) }
            }
            'B' { return }
            '' { return }
        }
    }
}

function Show-SettingsMenu {
    while ($true) {
        Show-Header 'Settings'
        $s = $script:Cfg.Settings
        $onoff = { param($v) if ($v) { 'On' } else { 'Off' } }
        $items = @(
            @('1', 'Report directory', [string]$s.ReportDir),
            @('2', 'Recent file window (days)', [string]$s.RecentDays),
            @('3', 'File scan depth (folders)', [string]$s.FileDepth),
            @('4', 'ANSI colors', ([string]$s.Ansi + ' (auto/on/off)')),
            @('5', 'Unicode borders and icons', (& $onoff $s.Unicode)),
            @('6', 'Animations', (& $onoff $s.Animations)),
            @('7', 'Logging verbosity', [string]$s.LogLevel),
            @('8', 'Scan category: memory integrity', (& $onoff $s.ScanMemory)),
            @('9', 'Scan category: files (Lua, data folders, recent files)', (& $onoff $s.ScanFiles)),
            @('10', 'Scan category: execution traces (BAM/Prefetch/processes)', (& $onoff $s.ScanTraces)),
            @('11', 'Known indicator database', ([string]@($script:Cfg.Tokens).Count + ' names, ' + [string]@($script:Cfg.Hashes).Count + ' hashes')),
            @('12', 'Reset all settings to defaults', '')
        )
        foreach ($it in $items) {
            Write-Seg ('  [' + $it[0].PadLeft(2) + '] ') 'Cyan' -NoNewline
            Write-Seg ($it[1].PadRight(58)) 'White' -NoNewline
            Write-Seg (Format-PathCut $it[2] ([Math]::Max(10, $script:W - 70))) 'Gray'
        }
        Write-Seg '  [ B] Back' 'Cyan'
        Write-Host ''
        $c = (Read-Choice 'Select').ToUpper()
        switch ($c) {
            '1' {
                $v = Read-Choice 'New report directory'
                if ($v) {
                    try { if (-not (Test-Path -LiteralPath $v)) { New-Item -ItemType Directory -Path $v -Force | Out-Null }; $s.ReportDir = $v; [void](Export-Config) }
                    catch { Write-Status bad ('Cannot use that folder: ' + $_.Exception.Message); Start-Sleep -Milliseconds 1500 }
                }
            }
            '2' { $n = 0; if ([int]::TryParse((Read-Choice 'Days (1-90)'), [ref]$n) -and $n -ge 1 -and $n -le 90) { $s.RecentDays = $n; [void](Export-Config) } else { Write-Status warn 'Enter a number from 1 to 90.'; Start-Sleep -Milliseconds 1000 } }
            '3' { $n = 0; if ([int]::TryParse((Read-Choice 'Depth (1-6)'), [ref]$n) -and $n -ge 1 -and $n -le 6) { $s.FileDepth = $n; [void](Export-Config) } else { Write-Status warn 'Enter a number from 1 to 6.'; Start-Sleep -Milliseconds 1000 } }
            '4' {
                $v = (Read-Choice 'ANSI mode (auto/on/off)').ToLower()
                if (@('auto', 'on', 'off') -contains $v) { $s.Ansi = $v; [void](Export-Config); Initialize-Console } else { Write-Status warn 'Choose auto, on or off.'; Start-Sleep -Milliseconds 1000 }
            }
            '5' { $s.Unicode = -not $s.Unicode; [void](Export-Config); Set-Glyphs }
            '6' { $s.Animations = -not $s.Animations; [void](Export-Config) }
            '7' { if ($s.LogLevel -eq 'Normal') { $s.LogLevel = 'Verbose' } else { $s.LogLevel = 'Normal' }; [void](Export-Config) }
            '8' { $s.ScanMemory = -not $s.ScanMemory; [void](Export-Config) }
            '9' { $s.ScanFiles = -not $s.ScanFiles; [void](Export-Config) }
            '10' { $s.ScanTraces = -not $s.ScanTraces; [void](Export-Config) }
            '11' { Show-IndicatorMenu }
            '12' {
                $ok = Read-Choice 'Reset settings, allowlist and indicator database to defaults? (Y/N)'
                if ($ok -match '^[Yy]') { $script:Cfg = New-DefaultConfig; [void](Export-Config); Initialize-Console }
            }
            'B' { return }
            '' { return }
            default { Write-Status warn 'Unknown option.'; Start-Sleep -Milliseconds 700 }
        }
    }
}

# ---------------------------------------------------------------------------
# Main menu / startup
# ---------------------------------------------------------------------------
function Show-Dashboard {
    $procs = @(Get-BedrockProc)
    $c = Get-Counts
    $running = 'Not running'; $rc = 'Red'
    if ($procs.Count -gt 0) { $running = 'Running (PID ' + (($procs | ForEach-Object { $_.Id }) -join ', ') + ')'; $rc = 'Green' }
    $ver = ''
    if ($procs.Count -gt 0) { $ver = Get-McVersion }
    if (-not $ver) { $ver = 'unavailable' }
    $adm = 'No (some checks limited)'; $ac = 'Yellow'
    if (Test-IsAdmin) { $adm = 'Yes'; $ac = 'Green' }
    $last = 'never'; if ($script:LastScan) { $last = $script:LastScan.ToString('yyyy-MM-dd HH:mm:ss') }
    $hc = 'Gray'; if ($c.High -gt 0) { $hc = 'Red' } elseif ($c.Suspicious -gt 0) { $hc = 'Yellow' }
    Write-Rule 'top'
    Write-Row @( @('Minecraft Bedrock   ', 'DarkGray'), @($running, $rc))
    Write-Row @( @('Windows user        ', 'DarkGray'), @($env:USERNAME, 'White'), @('   Administrator: ', 'DarkGray'), @($adm, $ac))
    Write-Row @( @('Minecraft version   ', 'DarkGray'), @($ver, 'White'))
    Write-Row @( @('Scan status         ', 'DarkGray'), @('Idle', 'Green'), @('   Last scan: ', 'DarkGray'), @($last, 'White'))
    Write-Row @( @('Inspected           ', 'DarkGray'), @("$($script:SeenFiles.Count) files, $($script:SeenModules.Count) modules", 'White'))
    Write-Row @( @('Findings            ', 'DarkGray'), @("$($c.High) high confidence, $($c.Suspicious) suspicious", $hc))
    Write-Row @( @('Scanner / database  ', 'DarkGray'), @("v$($script:Version) / $($script:DbVersion)", 'White'), @("   Publisher: $($script:Publisher)", 'DarkGray'))
    Write-Rule 'bot'
}

function Show-MainMenu {
    Show-Header -Full
    Show-Dashboard
    Write-Host ''
    $items = @(
        @(1, 'Full System Scan', 'Run every module and save an evidence report'),
        @(2, 'DLL Scanner', 'Inspect DLLs loaded in Minecraft and in its data folders'),
        @(3, 'Lua Scanner', 'Find and read-check Lua scripts'),
        @(4, 'Injection Investigation', 'Injector traces: BAM, Prefetch, running processes'),
        @(5, 'Minecraft Process Inspector', 'Process facts and module breakdown'),
        @(6, 'Memory Integrity Scanner', 'Detect manually mapped code in game memory'),
        @(7, 'Recent File Activity', 'Recently created/changed DLL, Lua, EXE and archives'),
        @(8, 'Digital Signature Scanner', 'Signature status of non-system modules'),
        @(9, 'Hash Scanner', 'SHA-256 of added modules/files vs the indicator database'),
        @(10, 'Evidence Reports', 'View, compare and save reports'),
        @(11, 'Allowlist Management', 'Legitimate software that should not be flagged'),
        @(12, 'Settings', 'Scan options, report folder, appearance, indicators'),
        @(13, 'Exit', '')
    )
    foreach ($it in $items) {
        Write-Seg ('  [' + ([string]$it[0]).PadLeft(2) + '] ') 'Cyan' -NoNewline
        Write-Seg ($it[1].PadRight(30)) 'White' -NoNewline
        Write-Seg (Format-Cut $it[2] ($script:W - 42)) 'DarkGray'
    }
    Write-Host ''
}

function Start-BedrockSS {
    Import-Config
    Initialize-Native
    Initialize-Console
    try { $Host.UI.RawUI.WindowTitle = 'BEDROCK SS - by ' + $script:Publisher } catch { }

    Show-Header -Full
    Write-Status ok ('Scanner v' + $script:Version + ' by ' + $script:Publisher + ' (indicator database ' + $script:DbVersion + ')')
    Write-Status ok 'Read-only inspection mode: nothing on this PC is modified, deleted, uploaded or executed.'
    if ($script:NativeOk) { Write-Status ok 'Memory inspection helper ready.' } else { Write-Status warn 'Memory inspection helper unavailable; the memory scan will be skipped.' }
    $adm = Test-IsAdmin
    if ($adm) { Write-Status ok 'Running as Administrator.' }
    else {
        Write-Status warn 'Not running as Administrator. Memory, BAM and Prefetch checks may be limited.'
        if ($script:SelfPath) {
            $a = Read-Choice 'Relaunch as Administrator now? (Y/N)'
            if ($a -match '^[Yy]') {
                try {
                    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $script:SelfPath + '"'))
                    return
                } catch { Write-Status warn 'Elevation was cancelled. Continuing without Administrator rights.' }
            }
        }
    }
    if ($script:Cfg.Settings.Animations) { Start-Sleep -Milliseconds 700 }

    while ($true) {
        Show-MainMenu
        $choice = Read-Choice 'Select an option (1-13)'
        $num = 0
        if (-not [int]::TryParse($choice, [ref]$num) -or $num -lt 1 -or $num -gt 13) {
            Write-Status warn 'Invalid selection. Please enter a number from 1 to 13.'
            Start-Sleep -Milliseconds 1000
            continue
        }
        try {
            switch ($num) {
                1  { Invoke-ScanAction 'Full System Scan' { Invoke-FullScan } }
                2  { Invoke-ScanAction 'DLL Scanner' { Invoke-DllScan } }
                3  { Invoke-ScanAction 'Lua Scanner' { Invoke-LuaScan } }
                4  { Invoke-ScanAction 'Injection Investigation' { Invoke-InjectionScan; Invoke-Correlation } }
                5  { Show-ProcessInspector }
                6  { Invoke-ScanAction 'Memory Integrity Scanner' { Invoke-MemoryScan } }
                7  { Invoke-ScanAction 'Recent File Activity' { Invoke-RecentFileScan } }
                8  { Invoke-ScanAction 'Digital Signature Scanner' { Invoke-SignatureScan } }
                9  { Invoke-ScanAction 'Hash Scanner' { Invoke-HashScan } }
                10 { Show-ReportsMenu }
                11 { Show-AllowlistMenu }
                12 { Show-SettingsMenu }
                13 {
                    Show-Header 'Goodbye'
                    Write-Status ok 'Closing BEDROCK SS. Evidence reports remain in the report folder.'
                    Write-Host ''
                    return
                }
            }
        } catch {
            Write-Status bad ('Unexpected error: ' + $_.Exception.Message)
            Write-Log 'ERROR' ('Menu action failed: ' + $_.Exception.Message)
            $script:Busy = $false
            Wait-Enter
        }
    }
}

Start-BedrockSS

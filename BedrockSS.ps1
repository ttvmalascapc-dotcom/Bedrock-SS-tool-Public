# BedrockSS.ps1 - Minecraft Bedrock screenshare scanner
# Run from cmd (admin or not):
#   powershell -NoP -EP Bypass -c "irm <RAW LINK TO THIS FILE> | iex"
# Flags are leads for the screensharer to review, not proof of cheating.

# Raw link to THIS file once you host it (used to relaunch as admin).
$ScriptUrl = 'PUT_YOUR_RAW_LINK_HERE'

# Name tokens matched against paths / file names. Add client names here.
$Tokens = @('onix','flarial','horion','nuvola','zephyr','fate','injector','inject','cheat','hack','client.dll')

$OverlaySigners = @('Microsoft','NVIDIA','Advanced Micro Devices','AMD','Intel','Discord','OBS Project','Valve',
    'Overwolf','Realtek','Razer','Logitech','Corsair','SteelSeries','Guru3D','MSI','ASUS','Google','Mozilla',
    'Epic Games','Xbox','Streamlabs','Medal','Wallpaper Engine','Dolby','Waves Audio')

function Invoke-BedrockSS {

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host 'Not running as Administrator - relaunching elevated (click Yes)...' -ForegroundColor Yellow
        Start-Process powershell -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-Command',"irm '$ScriptUrl' | iex")
        return
    }

    Write-Host ''
    Write-Host 'BedrockSS - Minecraft Bedrock scanner' -ForegroundColor Magenta
    Write-Host 'Flags are leads to review, not proof of cheating.' -ForegroundColor Gray
    Write-Host ''

    $procs = @(Get-Process -Name 'Minecraft.Windows' -ErrorAction SilentlyContinue)
    if ($procs.Count -eq 0) {
        Write-Host 'Minecraft.Windows.exe is not running. Open Bedrock, join a world, then run again.' -ForegroundColor Red
        return
    }

    $findings = New-Object System.Collections.ArrayList
    function Add-Finding($sev, $src, $title, $details) {
        [void]$findings.Add([pscustomobject]@{ Sev = $sev; Src = $src; Title = $title; Details = @($details) })
    }
    $rank = @{ High = 3; Medium = 2; Low = 1; Info = 0 }

    function Test-Like($text, $patterns) {
        foreach ($p in $patterns) { if ($text -like "*$p*") { return $true } }
        return $false
    }
    $userDirs = @('\Downloads\','\Temp\','\Desktop\','\AppData\','\Documents\','\Users\Public\','\ProgramData\','\OneDrive\')
    $gameDirs = @('\WindowsApps\Microsoft.Minecraft','\WindowsApps\Microsoft.GamingServices','\XboxGames\Minecraft')

    # ------------------------------------------------------------------
    # 1. Loaded modules
    # ------------------------------------------------------------------
    Write-Host 'Checking loaded modules...' -ForegroundColor Gray
    $r = New-Object System.Collections.ArrayList
    function R($s, $m) { [void]$r.Add(@($s, $m)) }

    foreach ($p in $procs) {
        $mods = $null
        try { $mods = $p.Modules } catch {
            Add-Finding 'Low' 'Modules' "Could not read modules of PID $($p.Id)" $_.Exception.Message
            continue
        }

        foreach ($m in $mods) {
            $path = $m.FileName
            $name = $m.ModuleName
            $r.Clear()

            $exists = Test-Path -LiteralPath $path
            $sigStatus = 'Unknown'; $signer = ''; $company = ''; $desc = ''; $orig = ''; $sha = ''

            if (-not $exists) {
                R 'High' 'Loaded in memory but the file is missing from disk (deleted or moved after load).'
            } else {
                $sig = Get-AuthenticodeSignature -LiteralPath $path
                $sigStatus = $sig.Status.ToString()
                if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'CN=([^,]+)') { $signer = $Matches[1].Trim('"') }
                $vi = (Get-Item -LiteralPath $path -Force).VersionInfo
                if ($vi) { $company = $vi.CompanyName; $desc = $vi.FileDescription; $orig = $vi.OriginalFilename }
            }

            $inSystem = $path.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)
            $inGame = Test-Like $path $gameDirs
            $userW = Test-Like $path $userDirs
            $trusted = ($sigStatus -eq 'Valid')
            $overlay = $false
            if ($signer) { foreach ($o in $OverlaySigners) { if ($signer -like "*$o*") { $overlay = $true } } }

            $lower = $path.ToLower()
            if (-not ($trusted -and ($inSystem -or $inGame))) {
                foreach ($t in $Tokens) {
                    if ($lower.Contains($t)) { R 'High' "Path matches signature token `"$t`"."; break }
                }
            }

            if ($exists) {
                switch ($sigStatus) {
                    'NotSigned' {
                        if ($userW) { R 'High' 'Unsigned DLL loaded from a user-writable location.' }
                        elseif (-not $inSystem -and -not $inGame) { R 'High' 'Unsigned DLL loaded from outside system/game folders.' }
                        else { R 'Medium' 'Unsigned DLL inside a system/game folder (unusual).' }
                    }
                    'Valid' {
                        if ($userW -and -not $overlay) { R 'Medium' "Signed by `"$signer`" but loaded from a user-writable location." }
                        elseif (-not $inSystem -and -not $inGame -and -not $overlay) { R 'Low' "Signed by unrecognized publisher `"$signer`" and loaded outside system/game folders." }
                    }
                    'NotSupportedFileFormat' { R 'Low' 'Could not verify signature.' }
                    'Unknown' { R 'Low' 'Could not verify signature.' }
                    default { R 'High' "Signature failed validation ($sigStatus): tampered, self-signed or untrusted." }
                }
            }

            if ($r.Count -gt 0) {
                $top = 'Low'
                foreach ($x in $r) { if ($rank[$x[0]] -gt $rank[$top]) { $top = $x[0] } }
                if ($exists) {
                    try { $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() } catch { }
                }
                $d = @("Path:      $path", "Signature: $sigStatus$(if ($signer) { ' - ' + $signer })")
                if ($company -or $desc) { $d += "File info: company=[$company] description=[$desc] original name=[$orig]" }
                if ($sha) { $d += "SHA-256:   $sha" }
                foreach ($x in $r) { $d += "[$($x[0])] $($x[1])" }
                Add-Finding $top 'Module' $name $d
            }
        }
    }

    # ------------------------------------------------------------------
    # 2. Manually mapped / reflectively loaded code
    # ------------------------------------------------------------------
    Write-Host 'Scanning memory for manually mapped code...' -ForegroundColor Gray
    if (-not ('MemScan' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class MemScan {
    [StructLayout(LayoutKind.Sequential)]
    struct MBI {
        public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
        public ushort PartitionId; public UIntPtr RegionSize; public uint State; public uint Protect; public uint Type;
    }
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint a, bool i, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern UIntPtr VirtualQueryEx(IntPtr h, IntPtr a, out MBI m, UIntPtr l);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, UIntPtr s, out UIntPtr r);

    static bool Exec(uint p) { return (p & 0xF0) != 0; }

    public static List<string> Scan(int pid) {
        var res = new List<string>();
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) { res.Add("ERR|" + Marshal.GetLastWin32Error()); return res; }
        try {
            var regs = new List<long[]>();
            long addr = 0;
            int sz = Marshal.SizeOf(typeof(MBI));
            while (addr >= 0 && addr < 0x7FFFFFFF0000L) {
                MBI m;
                if (VirtualQueryEx(h, (IntPtr)addr, out m, (UIntPtr)(uint)sz) == UIntPtr.Zero) break;
                long size = (long)(ulong)m.RegionSize;
                if (m.State == 0x1000 && m.Type != 0x1000000)
                    regs.Add(new long[] { m.BaseAddress.ToInt64(), m.AllocationBase.ToInt64(), size, (long)m.Protect });
                long next = m.BaseAddress.ToInt64() + size;
                if (next <= addr) break;
                addr = next;
            }
            var exec = new HashSet<long>();
            foreach (var r in regs) if (Exec((uint)r[3])) exec.Add(r[1]);
            int rwx = 0;
            foreach (var r in regs) {
                if (r[0] != r[1] || !exec.Contains(r[1])) continue;
                byte[] buf = new byte[0x400];
                int want = (int)Math.Min(r[2], (long)buf.Length);
                UIntPtr got;
                if (want >= 0x40 && ReadProcessMemory(h, (IntPtr)r[0], buf, (UIntPtr)(uint)want, out got)
                    && (ulong)got >= 0x40 && buf[0] == (byte)'M' && buf[1] == (byte)'Z') {
                    int pe = BitConverter.ToInt32(buf, 0x3C);
                    if (pe > 0 && pe + 4 <= (int)(ulong)got && buf[pe] == (byte)'P' && buf[pe + 1] == (byte)'E' && buf[pe + 2] == 0 && buf[pe + 3] == 0) {
                        res.Add("PE|" + r[0].ToString("X") + "|" + r[2]);
                        continue;
                    }
                }
                if (r[3] == 0x40 && r[2] >= 0x10000 && rwx < 15) {
                    rwx++;
                    res.Add("RWX|" + r[0].ToString("X") + "|" + r[2]);
                }
            }
        } finally { CloseHandle(h); }
        return res;
    }
}
'@
    }

    foreach ($p in $procs) {
        $hits = [MemScan]::Scan($p.Id)
        $pe = 0
        foreach ($h in $hits) {
            $parts = $h.Split('|')
            switch ($parts[0]) {
                'ERR' { Add-Finding 'Low' 'Memory' "Could not open PID $($p.Id) for memory scan" "Win32 error $($parts[1])." }
                'PE'  { $pe++; Add-Finding 'High' 'Memory' "PE image mapped outside the module list (PID $($p.Id))" @("Address 0x$($parts[1]), $([int64]$parts[2]) bytes.", 'Executable code with a PE header and no file behind it = manually mapped / reflectively loaded DLL.') }
                'RWX' { Add-Finding 'Low' 'Memory' "Large RWX private region (PID $($p.Id))" "Address 0x$($parts[1]), $([int64]$parts[2]) bytes. Weak lead: drivers/JIT can do this too." }
            }
        }
        if ($pe -eq 0) { Write-Host "  No mapped PE images found in PID $($p.Id) (header-wiped mappers can still evade this)." -ForegroundColor DarkGray }
    }

    # ------------------------------------------------------------------
    # 3. .dll / .lua files and client folders
    # ------------------------------------------------------------------
    Write-Host 'Looking for .dll / .lua files and client folders...' -ForegroundColor Gray
    $pkg = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe'
    foreach ($sub in 'RoamingState','LocalState') {
        $root = Join-Path $pkg $sub
        if (-not (Test-Path $root)) { continue }
        foreach ($d in Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue) {
            $hit = $null
            foreach ($t in $Tokens) { if ($d.Name.ToLower().Contains($t)) { $hit = $t; break } }
            if ($hit) { Add-Finding 'High' 'Files' "Client-like folder in game data: $($d.Name)" $d.FullName }
            else { Add-Finding 'Info' 'Files' "Folder in game data: $sub\$($d.Name)" $d.FullName }
        }
        $files = Get-ChildItem -LiteralPath $root -Recurse -Depth 4 -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.dll', '.lua' }
        foreach ($f in $files) {
            $kind = if ($f.Extension -eq '.lua') { 'Lua script' } else { 'DLL' }
            Add-Finding 'Medium' 'Files' "$kind inside Bedrock data folder: $($f.Name)" @($f.FullName, "Modified $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')), $($f.Length) bytes")
        }
    }

    $scanRoots = @(
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'Documents'),
        $env:TEMP,
        'C:\Users\Public'
    )
    $exts = '.dll','.lua','.exe','.zip','.rar','.7z','.bat','.ps1'
    foreach ($root in $scanRoots) {
        if (-not (Test-Path $root)) { continue }
        $files = Get-ChildItem -LiteralPath $root -Recurse -Depth 3 -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in $exts }
        foreach ($f in $files) {
            $hit = $null
            foreach ($t in $Tokens) { if ($f.Name.ToLower().Contains($t)) { $hit = $t; break } }
            if ($hit) {
                Add-Finding 'Medium' 'Files' "File name matches `"$hit`": $($f.Name)" @($f.FullName, "Modified $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))")
            }
        }
    }

    foreach ($root in @($env:APPDATA, $env:LOCALAPPDATA)) {
        foreach ($d in Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue) {
            foreach ($t in $Tokens) {
                if ($d.Name.ToLower().Contains($t)) { Add-Finding 'High' 'Files' "AppData folder matches `"$t`"" $d.FullName; break }
            }
        }
    }

    # ------------------------------------------------------------------
    # 4. Execution history (BAM + Prefetch)
    # ------------------------------------------------------------------
    Write-Host 'Checking execution history...' -ForegroundColor Gray
    $bamRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
    if (-not (Test-Path $bamRoot)) { $bamRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings' }
    if (Test-Path $bamRoot) {
        $entries = @()
        foreach ($sid in Get-ChildItem $bamRoot -ErrorAction SilentlyContinue) {
            $key = Get-Item -LiteralPath $sid.PSPath
            foreach ($vn in $key.GetValueNames()) {
                $v = $key.GetValue($vn)
                if ($v -is [byte[]] -and $v.Length -ge 8) {
                    $ft = [BitConverter]::ToInt64($v, 0)
                    if ($ft -gt 0) { $entries += [pscustomobject]@{ Time = [DateTime]::FromFileTimeUtc($ft).ToLocalTime(); Path = $vn } }
                }
            }
        }
        $cutoff = (Get-Date).AddDays(-14)
        $shown = 0
        foreach ($e in ($entries | Where-Object { $_.Time -ge $cutoff } | Sort-Object Time -Descending)) {
            $hit = $null
            foreach ($t in $Tokens) { if ($e.Path.ToLower().Contains($t)) { $hit = $t; break } }
            $userFolder = Test-Like $e.Path @('\Downloads\','\Desktop\','\Temp\','\Users\Public\')
            $line = "$($e.Time.ToString('yyyy-MM-dd HH:mm'))  $($e.Path)"
            if ($hit) { Add-Finding 'High' 'BAM' "Recently run, matches `"$hit`"" $line }
            elseif ($userFolder -and $shown -lt 25) { $shown++; Add-Finding 'Low' 'BAM' 'Recently run from a user folder' $line }
        }
    } else {
        Add-Finding 'Low' 'BAM' 'BAM registry key not found' 'Older Windows build, or the key was removed.'
    }

    $pf = Join-Path $env:SystemRoot 'Prefetch'
    if (-not (Test-Path $pf)) {
        Add-Finding 'Medium' 'Prefetch' 'Prefetch folder missing' $pf
    } else {
        $pfFiles = @(Get-ChildItem -LiteralPath $pf -Filter *.pf -ErrorAction SilentlyContinue)
        if ($pfFiles.Count -eq 0) {
            Add-Finding 'Medium' 'Prefetch' 'Prefetch folder is empty' 'Cleared, or the SysMain service is disabled. Ask the player why.'
        }
        foreach ($f in $pfFiles) {
            foreach ($t in $Tokens) {
                if ($f.Name.ToLower().Contains($t)) {
                    Add-Finding 'High' 'Prefetch' "Prefetch entry matches `"$t`"" "$($f.Name)  (last written $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))"
                    break
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    $colors = @{ High = 'Red'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }
    $sorted = $findings | Sort-Object @{ Expression = { $rank[$_.Sev] }; Descending = $true }, Src

    $cH = @($findings | Where-Object { $_.Sev -eq 'High' }).Count
    $cM = @($findings | Where-Object { $_.Sev -eq 'Medium' }).Count
    $cL = @($findings | Where-Object { $_.Sev -eq 'Low' }).Count

    Write-Host ''
    Write-Host ('=' * 78)
    Write-Host " SCAN SUMMARY:  HIGH $cH  |  MEDIUM $cM  |  LOW $cL"
    Write-Host ('=' * 78)

    foreach ($f in $sorted) {
        Write-Host ''
        Write-Host "[$($f.Sev.ToUpper())] ($($f.Src)) $($f.Title)" -ForegroundColor $colors[$f.Sev]
        foreach ($line in $f.Details) { if ($line) { Write-Host "  $line" } }
    }

    if (($cH + $cM + $cL) -eq 0) {
        Write-Host ''
        Write-Host 'Nothing suspicious found.' -ForegroundColor Green
    }

    Write-Host ''
    Write-Host 'NOTE: a clean result is not proof. Check recent files, the recycle bin, and watch their screen.' -ForegroundColor DarkGray

    $out = Join-Path ([Environment]::GetFolderPath('Desktop')) ("BedrockSS_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".txt")
    try {
        $lines = foreach ($f in $sorted) { "[$($f.Sev.ToUpper())] ($($f.Src)) $($f.Title)"; foreach ($l in $f.Details) { "  $l" }; '' }
        Set-Content -Path $out -Value $lines -Encoding UTF8
        Write-Host "Report saved: $out" -ForegroundColor Gray
    } catch { }
}

Invoke-BedrockSS

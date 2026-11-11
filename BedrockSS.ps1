# BedrockSS.ps1 - Minecraft Bedrock screenshare scanner
# Run from cmd (admin or not):
#   powershell -NoP -EP Bypass -c "irm <RAW LINK TO THIS FILE> | iex"
# Flags are leads for the screensharer to review, not proof of cheating.

# Raw link to THIS file once you host it (used to relaunch as admin).
$ScriptUrl = 'https://raw.githubusercontent.com/ttvmalascapc-dotcom/Bedrock-SS-tool-Public/main/BedrockSS.ps1'

# Clients whose MAIN dll is allowed. Only extra DLLs added besides these get flagged.
#   Names  = file-name pieces of the main DLL (matched against the DLL's file name only)
#   Hashes = SHA-256 of the official DLL. With a hash, a DLL that is only NAMED like the client
#            but does not match is flagged as an impostor. Recommended: scan your own PC with the
#            real client loaded, copy its SHA-256 from the "Allowed" line, paste it here.
$AllowedClients = @(
    @{ Name = 'Flarial'; Names = @('flarial'); Hashes = @() },
    @{ Name = 'Oderso';  Names = @('oderso');  Hashes = @() }
)

# Name tokens matched against paths / file names. Add client names here.
$Tokens = @('onix','flarial','oderso','horion','nuvola','zephyr','fate','injector')

# What a name match means (shown in the report as "What it is").
$KnownNames = @{
    'flarial'    = 'Flarial client DLL'
    'oderso'     = 'Oderso client DLL'
    'onix'       = 'Onix client DLL'
    'fate'       = 'Fate injector - loads extra DLLs into the game'
    'horion'     = 'Horion client DLL'
    'nuvola'     = 'Nuvola client DLL'
    'zephyr'     = 'Zephyr client DLL'
    'injector'   = 'Injector - loads DLLs into other programs'
}

# Tokens that are scanned for: everything except the allowed clients' own names.
$ScanTokens = @($Tokens | Where-Object { $t = $_; -not (@($AllowedClients | Where-Object { $_.Names -contains $t }).Count) })

# Only DLLs/.lua in and around the game are scanned by default.
# Set to $true to also scan Downloads/Desktop/AppData names, BAM and Prefetch (noisier).
$ExtendedChecks = $false

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
    Write-Host 'Made by Malasca' -ForegroundColor Magenta
    Write-Host 'Flags are leads to review, not proof of cheating.' -ForegroundColor Gray
    Write-Host ''

    $procs = @(Get-Process -Name 'Minecraft.Windows' -ErrorAction SilentlyContinue)
    if ($procs.Count -eq 0) {
        Write-Host 'Minecraft.Windows.exe is not running. Open Bedrock, join a world, then run again.' -ForegroundColor Red
        return
    }

    function Set-Step($n, $text) {
        Write-Host "[$n/3] $text" -ForegroundColor Gray
        Write-Progress -Id 0 -Activity 'BedrockSS by Malasca' -Status "Step $n of 3: $text" -PercentComplete ((($n - 1) * 100) / 3)
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
    function Test-AllowedClient($fileName, $path, $sha) {
        $res = [pscustomobject]@{ State = 'none'; Client = ''; Reason = '' }
        $susp = Test-Like $path @('\Downloads\','\Desktop\','\Temp\','\Users\Public\')
        foreach ($c in $AllowedClients) {
            $hs = @($c.Hashes | ForEach-Object { $_.ToLower() })
            if ($sha -and ($hs -contains $sha)) { $res.State = 'hash'; $res.Client = $c.Name; return $res }
        }
        foreach ($c in $AllowedClients) {
            foreach ($pat in $c.Names) {
                if ($fileName.ToLower().Contains($pat)) {
                    $res.Client = $c.Name
                    if (@($c.Hashes).Count -gt 0) {
                        $res.State = 'impostor'
                        $res.Reason = "Named like $($c.Name) but its hash does not match the official DLL (modified, fake, or the client updated - recheck the hash)."
                    } elseif ($susp) {
                        $res.State = 'impostor'
                        $res.Reason = "Named like $($c.Name) but loaded from Downloads/Desktop/Temp, not an installed location."
                    } else {
                        $res.State = 'name'
                    }
                    return $res
                }
            }
        }
        return $res
    }
    $userDirs = @('\Downloads\','\Temp\','\Desktop\','\AppData\','\Documents\','\Users\Public\','\ProgramData\','\OneDrive\')
    $gameDirs = @('\WindowsApps\Microsoft.Minecraft','\WindowsApps\Microsoft.GamingServices','\XboxGames\Minecraft')

    # ------------------------------------------------------------------
    # 1. Loaded modules
    # ------------------------------------------------------------------
    Set-Step 1 'Checking DLLs loaded into Minecraft'
    $r = New-Object System.Collections.ArrayList
    function Add-Reason($s, $m) { [void]$r.Add(@($s, $m)) }
    $overlayNames = New-Object System.Collections.ArrayList

    foreach ($p in $procs) {
        $mods = $null
        try { $mods = $p.Modules } catch {
            Add-Finding 'Low' 'Modules' "Could not read modules of PID $($p.Id)" $_.Exception.Message
            continue
        }

        $idx = 0
        $total = @($mods).Count
        foreach ($m in $mods) {
            $path = $m.FileName
            $name = $m.ModuleName
            $idx++
            Write-Progress -Id 1 -ParentId 0 -Activity 'Scanning loaded DLLs' -Status "$idx of $total - $name" -PercentComplete (($idx * 100) / [Math]::Max($total, 1))
            $r.Clear()

            $exists = Test-Path -LiteralPath $path
            $inSystem = $path.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)
            $inGame = Test-Like $path $gameDirs
            $userW = Test-Like $path $userDirs
            $added = (-not $inSystem) -and (-not $inGame)

            $sigStatus = 'Unknown'; $signer = ''; $company = ''; $desc = ''; $orig = ''; $sha = ''
            if ($exists) {
                $sig = Get-AuthenticodeSignature -LiteralPath $path
                $sigStatus = $sig.Status.ToString()
                if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'CN=([^,]+)') { $signer = $Matches[1].Trim('"') }
                $vi = (Get-Item -LiteralPath $path -Force).VersionInfo
                if ($vi) { $company = $vi.CompanyName; $desc = $vi.FileDescription; $orig = $vi.OriginalFilename }
                if ($added) { try { $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() } catch { } }
            }
            $trusted = ($sigStatus -eq 'Valid')
            $overlay = $false
            if ($signer) { foreach ($o in $OverlaySigners) { if ($signer -like "*$o*") { $overlay = $true } } }

            if (-not $exists) {
                Add-Reason 'High' 'Loaded in memory but the file is missing from disk (deleted or moved after load).'
            }

            # Allowed client main DLL: shown, not flagged.
            if ($exists -and $added) {
                $al = Test-AllowedClient $name $path $sha
                if ($al.State -eq 'hash' -or $al.State -eq 'name') {
                    $how = 'hash matches the official DLL'
                    if ($al.State -eq 'name') { $how = 'matched by file name only (add its SHA-256 to $AllowedClients to verify)' }
                    Add-Finding 'Info' 'Allowed' $name @(
                        "What it is   : $($al.Client) main client DLL (allowed)",
                        "Verified     : $how",
                        "Path         : $path",
                        "SHA-256      : $sha")
                    continue
                }
                if ($al.State -eq 'impostor') { Add-Reason 'High' $al.Reason }
            }

            $lower = $path.ToLower()
            $knownTok = $null
            foreach ($t in $ScanTokens) { if ($lower.Contains($t)) { $knownTok = $t; break } }
            if ($knownTok -and -not ($trusted -and ($inSystem -or $inGame))) {
                Add-Reason 'High' "Name matches known client/injector `"$knownTok`"."
            }

            if ($exists) {
                switch ($sigStatus) {
                    'NotSigned' {
                        if ($userW) { Add-Reason 'High' 'Unsigned DLL loaded from a user-writable folder.' }
                        elseif ($added) { Add-Reason 'High' 'Unsigned DLL loaded from outside the Windows/Minecraft folders.' }
                        else { Add-Reason 'Medium' 'Unsigned DLL inside a Windows/Minecraft folder (unusual).' }
                    }
                    'Valid' {
                        if ($userW -and -not $overlay) { Add-Reason 'Medium' "Signed by `"$signer`" but loaded from a user-writable folder." }
                        elseif ($added -and -not $overlay) { Add-Reason 'Low' "Signed by unrecognized publisher `"$signer`" and loaded outside the Windows/Minecraft folders." }
                    }
                    'NotSupportedFileFormat' { Add-Reason 'Low' 'Could not verify signature.' }
                    'Unknown' { Add-Reason 'Low' 'Could not verify signature.' }
                    default { Add-Reason 'High' "Signature failed validation ($sigStatus): tampered, self-signed or untrusted." }
                }
            }

            if ($r.Count -gt 0) {
                $top = 'Low'
                foreach ($x in $r) { if ($rank[$x[0]] -gt $rank[$top]) { $top = $x[0] } }
                if ($exists -and -not $sha) {
                    try { $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() } catch { }
                }

                $what = 'DLL added to Minecraft - not part of Windows or the game'
                if ($knownTok -and $KnownNames.ContainsKey($knownTok)) { $what = $KnownNames[$knownTok] }
                elseif ($sigStatus -eq 'NotSigned') { $what = 'Unsigned DLL added to Minecraft - no publisher, not part of Windows or the game' }
                elseif ($exists -and $sigStatus -ne 'Valid') { $what = 'DLL added to Minecraft with a broken or untrusted signature' }
                foreach ($c in $AllowedClients) {
                    foreach ($pat in $c.Names) {
                        if ($lower.Contains($pat)) { $what = "Extra DLL added alongside $($c.Name) - not its main client DLL" }
                    }
                }
                if (-not $exists) { $what = 'DLL still loaded in the game but deleted from disk (hiding its file)' }

                $d = @("What it is   : $what")
                $first = $true
                foreach ($x in $r) {
                    if ($first) { $d += "Why flagged  : $($x[1])"; $first = $false }
                    else { $d += "               $($x[1])" }
                }
                $d += "Path         : $path"
                $sg = $sigStatus; if ($signer) { $sg += " - $signer" }
                $d += "Signature    : $sg"
                if ($company -or $desc -or $orig) { $d += "Says it is   : $desc | company: $company | original name: $orig" }
                if ($sha) { $d += "SHA-256      : $sha" }
                Add-Finding $top 'DLL' $name $d
            }
            elseif ($added -and $overlay) { [void]$overlayNames.Add($name) }
        }
    }

    Write-Progress -Id 1 -Activity 'Scanning loaded DLLs' -Completed

    # ------------------------------------------------------------------
    # 2. Manually mapped / reflectively loaded code
    # ------------------------------------------------------------------
    Set-Step 2 'Scanning game memory for hidden/manually mapped code'
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
    Set-Step 3 'Checking Bedrock data folders for .dll / .lua files'
    $pkg = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe'
    foreach ($sub in 'RoamingState','LocalState') {
        $root = Join-Path $pkg $sub
        if (-not (Test-Path $root)) { continue }
        foreach ($d in Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue) {
            $hit = $null
            foreach ($t in $ScanTokens) { if ($d.Name.ToLower().Contains($t)) { $hit = $t; break } }
            if ($hit) { Add-Finding 'High' 'Files' "Client-like folder in game data: $($d.Name)" $d.FullName }
            else { Add-Finding 'Info' 'Files' "Folder in game data: $sub\$($d.Name)" $d.FullName }
        }
        $files = Get-ChildItem -LiteralPath $root -Recurse -Depth 4 -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.dll', '.lua' }
        foreach ($f in $files) {
            $meta = "Modified     : $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')), $($f.Length) bytes"
            if ($f.Extension -eq '.lua') {
                Add-Finding 'Medium' 'Script' $f.Name @(
                    'What it is   : Lua script inside the Bedrock data folder (clients run these inside the game)',
                    "Path         : $($f.FullName)", $meta)
                continue
            }
            $fsha = ''
            try { $fsha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower() } catch { }
            $al = Test-AllowedClient $f.Name $f.FullName $fsha
            if ($al.State -eq 'hash' -or $al.State -eq 'name') {
                Add-Finding 'Info' 'Allowed' $f.Name @("What it is   : $($al.Client) main client DLL (allowed)", "Path         : $($f.FullName)", "SHA-256      : $fsha")
            } elseif ($al.State -eq 'impostor') {
                Add-Finding 'High' 'DLL' $f.Name @("What it is   : DLL in the Bedrock data folder named like $($al.Client)", "Why flagged  : $($al.Reason)", "Path         : $($f.FullName)", $meta, "SHA-256      : $fsha")
            } else {
                Add-Finding 'Medium' 'DLL' $f.Name @('What it is   : DLL stored inside the Bedrock data folder (not a normal Minecraft file)', "Path         : $($f.FullName)", $meta, "SHA-256      : $fsha")
            }
        }
    }

    if ($ExtendedChecks) {
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
            foreach ($t in $ScanTokens) { if ($f.Name.ToLower().Contains($t)) { $hit = $t; break } }
            if ($hit) {
                Add-Finding 'Medium' 'Files' "File name matches `"$hit`": $($f.Name)" @($f.FullName, "Modified $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))")
            }
        }
    }

    foreach ($root in @($env:APPDATA, $env:LOCALAPPDATA)) {
        foreach ($d in Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue) {
            foreach ($t in $ScanTokens) {
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
            foreach ($t in $ScanTokens) { if ($e.Path.ToLower().Contains($t)) { $hit = $t; break } }
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
            foreach ($t in $ScanTokens) {
                if ($f.Name.ToLower().Contains($t)) {
                    Add-Finding 'High' 'Prefetch' "Prefetch entry matches `"$t`"" "$($f.Name)  (last written $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))"
                    break
                }
            }
        }
    }

    }

    Write-Progress -Id 0 -Activity 'BedrockSS by Malasca' -Completed

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
    $cA = @($findings | Where-Object { $_.Src -eq 'Allowed' }).Count
    Write-Host " SCAN SUMMARY:  HIGH $cH  |  MEDIUM $cM  |  LOW $cL  |  allowed client DLLs seen: $cA"
    Write-Host ('=' * 78)

    foreach ($f in $sorted) {
        Write-Host ''
        $col = $colors[$f.Sev]
        if ($f.Src -eq 'Allowed') { $col = 'Green' }
        Write-Host "[$($f.Sev.ToUpper())] $($f.Title)   ($($f.Src))" -ForegroundColor $col
        foreach ($line in $f.Details) { if ($line) { Write-Host "  $line" } }
    }

    if ($overlayNames.Count -gt 0) {
        Write-Host ''
        Write-Host ("Known overlay/driver DLLs (not flagged): " + (($overlayNames | Sort-Object -Unique) -join ', ')) -ForegroundColor DarkGray
    }

    if (($cH + $cM + $cL) -eq 0) {
        Write-Host ''
        Write-Host 'Nothing suspicious found.' -ForegroundColor Green
    }

    Write-Host ''
    Write-Host 'NOTE: a clean result is not proof. Check recent files, the recycle bin, and watch their screen.' -ForegroundColor DarkGray

    $out = Join-Path ([Environment]::GetFolderPath('Desktop')) ("BedrockSS_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".txt")
    try {
        $lines = foreach ($f in $sorted) { "[$($f.Sev.ToUpper())] $($f.Title)   ($($f.Src))"; foreach ($l in $f.Details) { "  $l" }; '' }
        Set-Content -Path $out -Value (@("BedrockSS by Malasca - $(Get-Date -Format 'yyyy-MM-dd HH:mm')", '') + @($lines)) -Encoding UTF8
        Write-Host "Report saved: $out" -ForegroundColor Gray
    } catch { }
}

Invoke-BedrockSS

#Requires -Version 5.1
<#
.SYNOPSIS
    Fetches and installs the CORE third-party tools from their real upstreams.

.DESCRIPTION
    This is the piece that makes the toolkit work on a CLEAN machine. The four
    core tools (Ghidra, x64dbg, REA, x64dbg-MCP) are deliberately NOT vendored
    (see docs/03-licencas.md): a fresh clone has no ghidra/, x64dbg/, rea-main/
    or x64dbg-mcp-server-main/. Without a fetch step the health-check can only
    report them missing and ask a human to fix it by hand — which is exactly the
    gap this script closes.

    It reads config/tools.json (the single source of truth) and, per tool:

      ghidra       GitHub release asset  ghidra_*_PUBLIC_*.zip  → ghidra/
      x64dbg       GitHub release asset  snapshot_*.zip         → x64dbg/
      rea          npm tarball rea-agents → rea-main/ (+ npm install)
      x64dbg-mcp   GitHub release asset  x64dbg-MCP-Server-*.zip → x64dbg/release/*/plugins
                   (builds from source with Zig only as a fallback)

    Nothing is executed without -Apply: by default it prints the plan and the
    upstream URLs it would use, exactly like bootstrap-windows.ps1.

    Security: TLS 1.2 is forced, GitHub asset digests (sha256) are verified, the
    npm tarball's registry integrity (sha512) is verified. A downloaded file that
    fails its checksum is discarded, never extracted.

.PARAMETER Tool
    One or more slugs from config/tools.json: ghidra, x64dbg, rea, x64dbg-mcp.
    Default: all four, in dependency order.

.PARAMETER Apply
    Actually download and install. Without it, dry-run.

.PARAMETER Force
    Re-install even when the marker already exists (a tool present is skipped
    otherwise).

.PARAMETER CacheDir
    Where downloads are kept between runs. Default: <root>/.cache/downloads
    (gitignored). Re-running reuses a cached file when its checksum matches.

.EXAMPLE
    PS> .\scripts\fetch-tools.ps1                       # plan only
    PS> .\scripts\fetch-tools.ps1 -Apply                # install all four
    PS> .\scripts\fetch-tools.ps1 -Tool rea -Apply      # just REA
    PS> .\scripts\fetch-tools.ps1 -Tool x64dbg-mcp -Apply -Force

.NOTES
    Never uses sudo/elevation. Writes only inside the repo tree (the four
    third-party dirs plus the download cache). Exit 0 = nothing failed.
#>
[CmdletBinding()]
param(
    [string[]]$Tool = @(),
    [switch]$Apply,
    [switch]$Force,
    [string]$CacheDir
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'lib\common.ps1')
$root = Get-RepoRoot
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

# TLS 1.2 for Windows PowerShell 5.1, whose default can still be TLS 1.0.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch { }

if (-not $CacheDir) { $CacheDir = Join-Path $root '.cache\downloads' }
$userAgent = 'UnboxRE-fetch-tools'

# ─── Result collection (JSON-contract friendly) ──────────────────────────────

function Get-ManifestTools {
    $tools = Get-ToolManifest
    if ($null -eq $tools) {
        Write-Status 'FAIL' 'config/tools.json ausente ou inválido' 'este arquivo é a fonte de verdade do fetch'
        exit 2
    }
    return $tools
}

function Get-ToolField {
    # Tolerant access into the JSON object (missing key is data, not an error).
    param($ToolObj, [string]$Name, $Default = $null)
    return (Get-Field $ToolObj $Name $Default)
}

# ─── Network helpers ─────────────────────────────────────────────────────────

function Invoke-JsonGet {
    param([Parameter(Mandatory)][string]$Uri)
    $headers = @{ 'User-Agent' = $userAgent; 'Accept' = 'application/vnd.github+json' }
    try {
        return Invoke-RestMethod -Uri $Uri -Headers $headers -TimeoutSec 60 -UseBasicParsing
    } catch {
        Write-Status 'FAIL' "GET $Uri falhou: $($_.Exception.Message)"
        return $null
    }
}

function Resolve-GithubAsset {
    <#
        Resolves the latest release of a GitHub repo and returns the asset whose
        name matches $Pattern: @{ Name; Url; Sha256; Size } or $null.
    #>
    param(
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][string]$Pattern
    )
    $rel = Invoke-JsonGet -Uri "https://api.github.com/repos/$Repo/releases/latest"
    if ($null -eq $rel) { return $null }
    foreach ($a in @($rel.assets)) {
        if ($a.name -match $Pattern) {
            $sha = $null
            $digest = Get-Field $a 'digest'
            if ($digest -and $digest -like 'sha256:*') { $sha = $digest.Substring(7) }
            return [pscustomobject]@{
                Name   = $a.name
                Url    = $a.browser_download_url
                Sha256 = $sha
                Size   = $a.size
                Tag    = $rel.tag_name
            }
        }
    }
    Write-Status 'FAIL' "nenhum asset casou /$Pattern/ no release $($rel.tag_name) de $Repo"
    return $null
}

function Resolve-NpmTarball {
    param(
        [Parameter(Mandatory)][string]$Package,
        [Parameter(Mandatory)][string]$Registry
    )
    $meta = Invoke-JsonGet -Uri "$Registry/$Package"
    if ($null -eq $meta) { return $null }
    $latest = $meta.'dist-tags'.latest
    $ver = Get-Field $meta.versions $latest
    if ($null -eq $ver) { return $null }
    return [pscustomobject]@{
        Name      = "$Package@$latest"
        Url       = $ver.dist.tarball
        Integrity = $ver.dist.integrity
        Sha256    = $null
        Size      = (Get-Field $ver.dist 'unpackedSize' 0)
        Version   = $latest
    }
}

function Save-Download {
    <#  Download to $Dest. Returns the uppercase SHA256, or $null on failure.  #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Dest
    )
    $dir = Split-Path -Parent $Dest
    if ($dir -and -not (Test-PathExists $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Write-Status 'INFO' "baixando $Uri"
    try {
        $req = [System.Net.HttpWebRequest]::Create($Uri)
        $req.UserAgent = $userAgent
        $req.Timeout = 600000
        $resp = $req.GetResponse()
        $in = $resp.GetResponseStream()
        $out = [System.IO.File]::Create($Dest)
        try { $in.CopyTo($out) } finally { $out.Close(); $in.Close(); $resp.Close() }
    } catch {
        Write-Status 'FAIL' "download falhou: $($_.Exception.Message)"
        if (Test-PathExists $Dest) { Remove-Item -LiteralPath $Dest -Force -ErrorAction SilentlyContinue }
        return $null
    }
    return (Get-FileHash -LiteralPath $Dest -Algorithm SHA256).Hash
}

function Test-NpmIntegrity {
    <#  Verifies a file against an SRI string like sha512-<base64>.  #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Integrity
    )
    if ($Integrity -notmatch '^(sha512|sha256|sha1)-(.+)$') { return $true }  # unsupported → don't block
    $alg = $Matches[1]; $b64 = $Matches[2]
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $sha = [System.Security.Cryptography.SHA512]::Create()
    if ($alg -eq 'sha256') { $sha = [System.Security.Cryptography.SHA256]::Create() }
    if ($alg -eq 'sha1') { $sha = [System.Security.Cryptography.SHA1]::Create() }
    $hash = $sha.ComputeHash($bytes)
    $actual = [Convert]::ToBase64String($hash)
    return ($actual -eq $b64)
}

function Get-Bytes {
    <#  Uses the cache when a matching file is already present and checks out.  #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$FileName,
        [string]$Sha256,
        [string]$Integrity
    )
    $dest = Join-Path $CacheDir $FileName
    if ((Test-PathExists $dest) -and (Test-PathExists $CacheDir)) {
        if ($Sha256) {
            $have = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
            if ($have -eq $Sha256.ToUpper()) { Write-Status 'OK' "cache: $FileName"; return $dest }
        } elseif ($Integrity) {
            if (Test-NpmIntegrity -Path $dest -Integrity $Integrity) { Write-Status 'OK' "cache: $FileName"; return $dest }
        }
    }
    if (-not $Apply) {
        Write-Status 'INFO' "DRY-RUN: baixaria $Url → $dest"
        return $null
    }
    $sha = Save-Download -Uri $Url -Dest $dest
    if ($null -eq $sha) { return $null }
    if ($Sha256 -and ($sha -ne $Sha256.ToUpper())) {
        Write-Status 'FAIL' "checksum sha256 divergente para $FileName" "esperado $Sha256, obtido $sha"
        Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
        return $null
    }
    if ($Integrity -and -not (Test-NpmIntegrity -Path $dest -Integrity $Integrity)) {
        Write-Status 'FAIL' "integridade npm divergente para $FileName"
        Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
        return $null
    }
    Write-Status 'OK' "baixado e verificado: $FileName"
    return $dest
}

# ─── Install helpers ─────────────────────────────────────────────────────────

function Expand-ZipInto {
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$DestDir
    )
    New-DirIfMissing -Path $DestDir -Apply | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $DestDir)
}

function Expand-TarGz {
    <#
        Extracts a .tgz with a tar that understands Windows paths.

        Why this wrapper exists (regression, 2026-10-13): a clean-machine run
        revealed that `tar` in PowerShell resolves to Git-for-Windows' GNU tar,
        which reads "C:\..." as a REMOTE host spec — it fails with
        "Cannot connect to C: resolve failed" and leaves the destination empty.
        The REA install silently produced a rea-main/ with only a lockfile.

        Windows ships bsdtar at %SystemRoot%\System32\tar.exe (Win10 1803+),
        which accepts Windows paths. Prefer it; fall back to GNU tar with
        --force-local (the flag that disables the remote-host interpretation).
        Returns $true only if the tool succeeded AND something was extracted.
    #>
    param(
        [Parameter(Mandatory)][string]$Archive,
        [Parameter(Mandatory)][string]$Dest
    )
    New-DirIfMissing -Path $Dest -Apply | Out-Null
    $sysTar = Join-Path $env:SystemRoot 'System32\tar.exe'
    $attempts = @()
    if ($env:SystemRoot -and (Test-PathExists $sysTar)) { $attempts += ,@($sysTar, @()) }
    $attempts += ,@('tar', @())
    $attempts += ,@('tar', @('--force-local'))
    foreach ($a in $attempts) {
        $exe = $a[0]
        [string[]]$extra = $a[1]
        try {
            & $exe @extra -xzf $Archive -C $Dest 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $entries = @(Get-ChildItem -LiteralPath $Dest -Force -ErrorAction SilentlyContinue)
                if ($entries.Count -gt 0) { return $true }
            }
        } catch { }
    }
    return $false
}

function Install-PluginZip {
    <#
        The MCP plugin zip mirrors x64dbg's layout but the two tools disagree on
        where "root" is (the zip nests x64/plugins, our tree nests
        release/x64/plugins). Rather than assume, we FIND every *.dp64/*.dp32 in
        the extracted tree and drop it in the matching x64dbg plugins folder.
    #>
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$DestRoot
    )
    $tmp = Join-Path $CacheDir ('extract-' + [System.IO.Path]::GetRandomFileName())
    New-DirIfMissing -Path $tmp -Apply | Out-Null
    try {
        Expand-ZipInto -ZipPath $ZipPath -DestDir $tmp
        $map = @(
            @{ Ext = '*.dp64'; Arch = 'x64' },
            @{ Ext = '*.dp32'; Arch = 'x32' }
        )
        $found = 0
        foreach ($m in $map) {
            $pluginsDir = Join-Path $DestRoot "release\$($m.Arch)\plugins"
            foreach ($f in @(Get-ChildItem -Path $tmp -Recurse -Filter $m.Ext -File -ErrorAction SilentlyContinue)) {
                New-DirIfMissing -Path $pluginsDir -Apply | Out-Null
                Copy-Item -LiteralPath $f.FullName -Destination $pluginsDir -Force
                Write-Status 'OK' "instalado: release/$($m.Arch)/plugins/$(Split-Path -Leaf $f.FullName)"
                $found++
            }
        }
        if ($found -eq 0) { Write-Status 'FAIL' 'nenhum .dp64/.dp32 no zip do plugin' 'o asset upstream mudou de formato' }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-PostInstall {
    param(
        [Parameter(Mandatory)][string]$Dir,
        [Parameter(Mandatory)][string[]]$Commands
    )
    foreach ($cmd in $Commands) {
        if (-not $Apply) { Write-Status 'INFO' "DRY-RUN: (cd $Dir) $cmd"; continue }
        Write-Status 'INFO' "(cd $Dir) $cmd"
        Push-Location $Dir
        try {
            $parts = $cmd -split '\s+'
            & $parts[0] @($parts[1..($parts.Count - 1)]) 2>&1 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
            if ($LASTEXITCODE -ne 0) { Write-Status 'WARN' "comando retornou $LASTEXITCODE`: $cmd" }
        } finally { Pop-Location }
    }
}

# ─── Per-tool install ────────────────────────────────────────────────────────

function Install-Tool {
    param(
        [Parameter(Mandatory)][string]$Slug,
        [Parameter(Mandatory)]$Meta
    )
    $name = Get-ToolField $Meta 'displayName' $Slug
    $install = Get-ToolField $Meta 'install'
    $method = Get-ToolField $install 'method'
    $dest = Join-Path $root (Get-ToolField $install 'dest')
    $marker = Get-ToolField $install 'marker'

    Write-Host ''
    Write-Host "── $name  [$Slug]" -ForegroundColor Cyan
    Write-Host ("   licença: " + (Get-ToolField (Get-ToolField $Meta 'license') 'spdx' '?')) -ForegroundColor DarkGray
    Write-Host ("   destino: " + $dest) -ForegroundColor DarkGray

    if ($marker -and -not $Force -and (Test-ToolMarker -Marker $marker)) {
        Write-Status 'OK' "$name já instalado ($marker)"
        return $true
    }

    $upstream = Get-ToolField $Meta 'upstream'
    $type = Get-ToolField $upstream 'type'

    if ($type -eq 'github-release') {
        $asset = Resolve-GithubAsset -Repo (Get-ToolField $upstream 'repo') -Pattern (Get-ToolField $upstream 'assetPattern')
        if ($null -eq $asset) { return $false }
        $minSize = Get-ToolField $upstream 'assetSizeBytesMin' 0
        if ($asset.Size -lt $minSize) {
            Write-Status 'FAIL' "asset $($asset.Name) tem $($asset.Size) bytes (< mínimo $minSize)"
            return $false
        }
        Write-Status 'INFO' "release $($asset.Tag) → $($asset.Name) ($([math]::Round($asset.Size / 1MB, 1)) MB)"
        $file = Get-Bytes -Url $asset.Url -FileName $asset.Name -Sha256 $asset.Sha256
        if ($null -eq $file) { if (-not $Apply) { return $true } else { return $false } }

        if ($method -eq 'plugin-zip') {
            Install-PluginZip -ZipPath $file -DestRoot $dest
        } else {
            Write-Status 'INFO' "extraindo em $dest"
            Expand-ZipInto -ZipPath $file -DestDir $dest
        }
        if ($marker -and -not (Test-ToolMarker -Marker $marker)) {
            Write-Status 'FAIL' "marker não encontrado após extração: $marker" 'layout upstream mudou?'
            return $false
        }
        return $true

    } elseif ($type -eq 'npm-package') {
        $pk = Resolve-NpmTarball -Package (Get-ToolField $upstream 'package') -Registry (Get-ToolField $upstream 'registry')
        if ($null -eq $pk) { return $false }
        Write-Status 'INFO' "npm $($pk.Name)"
        $file = Get-Bytes -Url $pk.Url -FileName ((Split-Path -Leaf $pk.Url)) -Integrity $pk.Integrity
        if ($null -eq $file) { if (-not $Apply) { return $true } else { return $false } }

        if ($Apply) {
            New-DirIfMissing -Path $dest -Apply | Out-Null
            # npm tarballs nest everything under package/ — strip it.
            $tmp = Join-Path $CacheDir ('extract-' + [System.IO.Path]::GetRandomFileName())
            New-DirIfMissing -Path $tmp -Apply | Out-Null
            try {
                if (-not (Expand-TarGz -Archive $file -Dest $tmp)) {
                    Write-Status 'FAIL' "não consegui extrair $((Split-Path -Leaf $file))" 'nenhum tar disponível funcionou (bsdtar e GNU tar falharam)'
                    return $false
                }
                $inner = Join-Path $tmp 'package'
                if (Test-PathExists $inner) {
                    Get-ChildItem -Path $inner -Force | ForEach-Object {
                        Copy-Item -LiteralPath $_.FullName -Destination $dest -Recurse -Force
                    }
                } else {
                    Get-ChildItem -Path $tmp -Force | ForEach-Object {
                        Copy-Item -LiteralPath $_.FullName -Destination $dest -Recurse -Force
                    }
                }
            } finally {
                Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
            }
        } else {
            Write-Status 'INFO' "DRY-RUN: extrairia $($pk.Url) em $dest"
        }
        $post = Get-ToolField $install 'postInstall'
        if ($post) { Invoke-PostInstall -Dir $dest -Commands @($post) }
        if ($Apply -and $marker -and -not (Test-ToolMarker -Marker $marker)) {
            Write-Status 'FAIL' "marker não encontrado: $marker"
            return $false
        }
        return $true
    }

    Write-Status 'FAIL' "tipo de upstream desconhecido: $type"
    return $false
}

# ─── Runner ──────────────────────────────────────────────────────────────────

$tools = Get-ManifestTools
$order = @('ghidra', 'x64dbg', 'rea', 'x64dbg-mcp')

if ($Tool.Count -eq 0 -or ($Tool -contains 'all')) {
    $selected = $order
} else {
    $selected = @($Tool | Where-Object { $tools.PSObject.Properties.Name -contains $_ })
    $unknown = @($Tool | Where-Object { -not ($tools.PSObject.Properties.Name -contains $_) })
    foreach ($u in $unknown) { Write-Status 'FAIL' "slug desconhecido: $u" ("use um destes: " + ($order -join ', ')) }
    if ($selected.Count -eq 0) { exit 2 }
}

Write-Banner 'UnboxRE — fetch de ferramentas do núcleo' ("raiz: $root")
Write-Host ("  modo:  " + $(if ($Apply) { 'APLICANDO (-Apply)' } else { 'dry-run (nada será baixado)' })) -ForegroundColor $(if ($Apply) { 'Yellow' } else { 'DarkGray' })
Write-Host ("  cache: $CacheDir") -ForegroundColor DarkGray
Write-Host ("  alvos: " + ($selected -join ', ')) -ForegroundColor DarkGray

$ok = 0; $fail = 0
foreach ($slug in $order) {
    if (-not ($selected -contains $slug)) { continue }
    $meta = $tools.$slug
    if ($null -eq $meta) { continue }
    if (Install-Tool -Slug $slug -Meta $meta) { $ok++ } else { $fail++ }
}

Write-Host ''
Write-Host ('─' * 68) -ForegroundColor DarkCyan
Write-Host ("  instalados/ok: $ok   falhas: $fail") -ForegroundColor $(if ($fail -gt 0) { 'Red' } else { 'Green' })

if ($Apply -and (Test-ToolMarker -Marker 'ghidra/*/support/analyzeHeadless.bat')) {
    $ghidraDir = (Resolve-GhidraHome)
    if ($ghidraDir -and $env:GHIDRA_INSTALL_DIR -ne $ghidraDir) {
        $env:GHIDRA_INSTALL_DIR = $ghidraDir
        $null = Set-EnvFileValue -Path (Join-Path $root 'config\env\unboxre.env') -Key 'GHIDRA_INSTALL_DIR' -Value $ghidraDir -Apply
        Write-Status 'OK' "GHIDRA_INSTALL_DIR ajustado para $ghidraDir" 'reinicie a sessão para herdar fora deste script'
    }
}

if (-not $Apply) {
    Write-Host ''
    Write-Host '  Isto foi um DRY-RUN. Rode de novo com -Apply para baixar e instalar.' -ForegroundColor Cyan
}
Write-Host ''
Write-Host '  Revalide com: .\scripts\health-check.ps1' -ForegroundColor DarkGray
Write-Host ''

if ($fail -gt 0) { exit 1 } else { exit 0 }

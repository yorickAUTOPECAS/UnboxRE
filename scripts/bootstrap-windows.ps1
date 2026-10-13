#Requires -Version 5.1
<#
.SYNOPSIS
    Instala as ferramentas do catálogo UnboxRE por perfil, de forma idempotente.

.DESCRIPTION
    Nada é instalado sem -Apply. Sem -Apply o script apenas mostra o plano,
    ferramenta por ferramenta, com o motivo de cada uma estar ali.

    Estratégia de instalação, em ordem de preferência:
      1. winget  — quando o Id foi verificado (o script confere no catálogo)
      2. choco   — para o que não existe no winget
      3. pip / npm / cargo — ferramentas que são bibliotecas
      4. manual  — imprime a URL e a razão; nunca finge que instalou

    Toda ferramenta já presente (detectada por Probe) é pulada. Rodar duas vezes
    não quebra nada.

.PARAMETER Profile
    core      toolchain de build (JDK, Node, Zig, CMake, Ninja, Rust, Python)
    static    análise estática (radare2, DIE, YARA, capa, retoolkit)
    dynamic   análise dinâmica (Frida, Wireshark, mitmproxy, QEMU)
    mobile    Android (jadx, apktool, WSL/Ubuntu)
    firmware  firmware/IoT (binwalk, unblob — via WSL)
    net       rede (tshark, mitmproxy, fluxzy)
    plugins   instala os plugins no x64dbg (delega a re-build.ps1)
    all       todos os perfis acima

.PARAMETER Apply
    Executa de fato. Sem esta flag, é dry-run.

.PARAMETER Method
    auto (padrão) | winget | choco | manual. `auto` usa winget e cai para choco.

.PARAMETER Yes
    Passa --accept-package-agreements/--accept-source-agreements e --silent.

.EXAMPLE
    PS> .\scripts\bootstrap-windows.ps1
    PS> .\scripts\bootstrap-windows.ps1 -Profile static -Apply
    PS> .\scripts\bootstrap-windows.ps1 -Profile all -Apply -Yes

.NOTES
    Nunca usa sudo/elevação automática. Se um pacote exigir admin, o winget/choco
    mostra o prompt do próprio instalador — você decide.
#>
[CmdletBinding()]
param(
    [ValidateSet('core', 'static', 'dynamic', 'mobile', 'firmware', 'net', 'plugins', 'all')]
    [string[]]$Profile = @('core'),

    [switch]$Apply,
    [ValidateSet('auto', 'winget', 'choco', 'manual')]
    [string]$Method = 'auto',
    [switch]$Yes
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'lib\common.ps1')
$root = Get-RepoRoot

try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

# ───────────────────────────────────────────────────────────────────────────
#  Catálogo de instalação
# ───────────────────────────────────────────────────────────────────────────
#
#  Campos:
#    Name     nome exibido
#    Probe    comando que, se existir, indica "já instalado"
#    Profiles perfis que incluem esta ferramenta
#    Winget   Id verificado via `winget search` (vazio = não existe no winget)
#    Choco    Id do Chocolatey (vazio = não existe)
#    Pip/Npm/Cargo  instalação como pacote
#    Url      fonte manual (sempre preenchida — é o fallback honesto)
#    Why      por que esta ferramenta está no toolkit
#    License  licença, para a checagem de compatibilidade MIT
#
#  Regra: um Id só entra aqui depois de verificado. Id inventado gera erro
#  obscuro na cara do usuário — pior que dizer "instale à mão".

$Catalog = @(
    # ── core: toolchain ────────────────────────────────────────────────────
    @{ Name = 'Zig'; Probe = 'zig'; Profiles = @('core'); Winget = 'zig.zig'; Url = 'https://ziglang.org/download/'
       Why = 'compila o x64dbg-MCP (build.zig.zon exige >= 0.14.0)'; License = 'MIT' }
    @{ Name = 'CMake'; Probe = 'cmake'; Profiles = @('core'); Winget = 'Kitware.CMake'; Url = 'https://cmake.org/download/'
       Why = 'builds nativos (QEMU, plugins de emulador)'; License = 'BSD-3' }
    @{ Name = 'Ninja'; Probe = 'ninja'; Profiles = @('core'); Winget = 'Ninja-build.Ninja'; Url = 'https://github.com/ninja-build/ninja/releases'
       Why = 'backend de build rápido para o CMake'; License = 'Apache-2.0' }
    @{ Name = 'Rust'; Probe = 'cargo'; Profiles = @('core'); Winget = 'Rustlang.Rustup'; Url = 'https://rustup.rs'
       Why = 'compila ferramentas RE em Rust (pe-sieve, yara-x, etc.)'; License = 'MIT/Apache-2.0' }
    @{ Name = 'Python 3.12'; Probe = 'python'; Profiles = @('core'); Winget = 'Python.Python.3.12'; Url = 'https://www.python.org/downloads/'
       Why = 'hospeda capa, frida-tools, unblob, pwntools, angr'; License = 'PSF' }
    @{ Name = 'Node.js LTS'; Probe = 'node'; Profiles = @('core'); Winget = 'OpenJS.NodeJS'; Url = 'https://nodejs.org/'
       Why = 'executa o REA e os scripts .mjs deste toolkit'; License = 'MIT' }

    # ── static ─────────────────────────────────────────────────────────────
    @{ Name = 'radare2'; Probe = 'r2'; Profiles = @('static'); Choco = 'radare2'; Url = 'https://github.com/radareorg/radare2/releases'
       Why = 'CLI/scriptável, r2pipe, diff de binários, sem GUI'; License = 'LGPL-3' }
    @{ Name = 'Rizin'; Probe = 'rizin'; Profiles = @('static'); Winget = 'Rizin.Rizin'; Url = 'https://rizin.re/'
       Why = 'fork do radare2 com foco em estabilidade e testes'; License = 'LGPL-3' }
    @{ Name = 'Detect It Easy'; Probe = 'diec'; Profiles = @('static'); Winget = 'horsicq.DIE-engine'; Url = 'https://github.com/horsicq/Detect-It-Easy'
       Why = 'identifica packer/compilador em segundos — primeira triagem'; License = 'MIT' }
    @{ Name = 'YARA'; Probe = 'yara'; Profiles = @('static'); Winget = 'VirusTotal.YARA'; Url = 'https://github.com/VirusTotal/yara/releases'
       Why = 'assinaturas para triagem em lote e detecção de família'; License = 'BSD-3' }
    @{ Name = 'YARA-X'; Probe = 'yr'; Profiles = @('static'); Winget = 'VirusTotal.YARA-X'; Url = 'https://github.com/VirusTotal/yara-x'
       Why = 'YARA reescrito em Rust; regras do YARA-X não rodam no YARA 4'; License = 'BSD-3' }
    @{ Name = 'capa'; Probe = 'capa'; Profiles = @('static'); Pip = 'flare-capa'; Url = 'https://github.com/mandiant/capa'
       Why = 'mapeia capacidades (MITRE ATT&CK/MBC) direto do binário'; License = 'Apache-2.0' }
    @{ Name = 'UPX'; Probe = 'upx'; Profiles = @('static'); Winget = 'UPX.UPX'; Url = 'https://github.com/upx/upx/releases'
       Why = 'unpack/repack UPX — o packer mais comum'; License = 'GPL-2' }
    @{ Name = 'retoolkit'; Probe = 'pe-sieve'; Profiles = @('static'); Winget = 'mentebinaria.retoolkit'; Url = 'https://github.com/mentebinaria/retoolkit'
       Why = 'coletânea portátil: pe-sieve, hollows_hunter, Scylla, etc.'; License = 'diversas (ver docs/03)' }

    # ── dynamic ────────────────────────────────────────────────────────────
    @{ Name = 'Frida tools'; Probe = 'frida'; Profiles = @('dynamic'); Pip = 'frida-tools'; Url = 'https://frida.re/docs/installation/'
       Why = 'instrumentação DBI sem recompilar o alvo'; License = 'wxWindows/LGPL' }
    @{ Name = 'Wireshark'; Probe = 'tshark'; Profiles = @('dynamic', 'net'); Winget = 'WiresharkFoundation.Wireshark'; Url = 'https://www.wireshark.org/download.html'
       Why = 'tshark/dumpcap para captura e dissecação scriptável'; License = 'GPL-2' }
    @{ Name = 'mitmproxy'; Probe = 'mitmdump'; Profiles = @('dynamic', 'net'); Winget = 'mitmproxy.mitmproxy'; Url = 'https://mitmproxy.org/'
       Why = 'interceptação HTTP(S) com addons Python'; License = 'MIT' }
    @{ Name = 'QEMU'; Probe = 'qemu-system-x86_64'; Profiles = @('dynamic', 'firmware'); Winget = 'SoftwareFreedomConservancy.QEMU'; Url = 'https://www.qemu.org/download/'
       Why = 'emulação de sistema para firmware e alvos Linux'; License = 'GPL-2' }
    @{ Name = 'Procmon (Sysinternals)'; Probe = 'procmon'; Profiles = @('dynamic'); Choco = 'sysinternals'; Url = 'https://learn.microsoft.com/sysinternals/downloads/procmon'
       Why = 'traço de file/registry/processo — sem ele, RE dinâmico fica cego'; License = 'proprietária-freeware' }
    @{ Name = 'API Monitor'; Probe = 'apimonitor'; Profiles = @('dynamic'); Url = 'http://www.rohitab.com/apimonitor'
       Why = 'traço de chamadas Win32/COM em nível de argumento'; License = 'freeware [COMERCIAL p/ x64 no passado]' }

    # ── mobile ─────────────────────────────────────────────────────────────
    @{ Name = 'jadx'; Probe = 'jadx'; Profiles = @('mobile'); Winget = 'Skylot.jadx'; Url = 'https://github.com/skylot/jadx/releases'
       Why = 'DEX → Java legível; melhor descompilador Android aberto'; License = 'Apache-2.0' }
    @{ Name = 'apktool'; Probe = 'apktool'; Profiles = @('mobile'); Choco = 'apktool'; Url = 'https://github.com/iBotPeaches/Apktool/releases'
       Why = 'desmonta/remonta APK (smali + recursos) — necessário para patch'; License = 'Apache-2.0' }
    @{ Name = 'WSL/Ubuntu'; Probe = 'wsl'; Profiles = @('mobile', 'firmware'); Winget = 'Canonical.Ubuntu'; Url = 'https://learn.microsoft.com/windows/wsl/install'
       Why = 'hospeda o toolchain Linux: unblob, pwndbg, angr, binwalk'; License = 'GPL-2 (kernel) / Ubuntu' }

    # ── firmware ───────────────────────────────────────────────────────────
    @{ Name = 'unblob'; Probe = 'unblob'; Profiles = @('firmware'); Pip = 'unblob'; Url = 'https://github.com/onekey-sec/unblob'
       Why = 'extração recursiva de firmware com detecção de formato'; License = 'MIT' }
    @{ Name = 'binwalk'; Probe = 'binwalk'; Profiles = @('firmware'); Url = 'https://github.com/ReFirmLabs/binwalk (usar dentro do WSL)'
       Why = 'recon clássico de firmware; mantenha para compatibilidade'; License = 'MIT' }
    @{ Name = 'ubireader'; Probe = 'ubireader_extract_images'; Profiles = @('firmware'); Pip = 'ubi_reader'; Url = 'https://github.com/jrspruitt/ubi_reader'
       Why = 'imagens UBI/UBIFS (roteadores e IoT em geral)'; License = 'GPL-3' }
    @{ Name = 'sasquatch'; Probe = 'sasquatch'; Profiles = @('firmware'); Url = 'https://github.com/onekey-sec/sasquatch (build no WSL)'
       Why = 'SquashFS com patches de fornecedor — o binwalk não lê'; License = 'GPL-2' }
    @{ Name = 'firmware-mod-kit'; Probe = 'unsquashfs_all.sh'; Profiles = @('firmware'); Url = 'https://github.com/rampageX/firmware-mod-kit (WSL)'
       Why = 'desempacota e reempacota firmware de roteador'; License = 'GPL-2' }

    # ── net ────────────────────────────────────────────────────────────────
    @{ Name = 'Fluxzy'; Probe = 'fluxzy'; Profiles = @('net'); Winget = 'Fluxzy.Fluxzy'; Url = 'https://www.fluxzy.io/'
       Why = 'proxy MITM .NET com export HAR e regras em C#'; License = 'GPL-3.0' }
)

# ───────────────────────────────────────────────────────────────────────────
#  Seleção de gerenciador
# ───────────────────────────────────────────────────────────────────────────

function Resolve-Manager {
    $haveWinget = Test-CommandExists 'winget'
    $haveChoco = Test-CommandExists 'choco'
    if ($Method -eq 'winget' -and -not $haveWinget) { return 'none' }
    if ($Method -eq 'choco' -and -not $haveChoco) { return 'none' }
    if ($Method -eq 'manual') { return 'manual' }
    if ($haveWinget) { return 'winget' }
    if ($haveChoco) { return 'choco' }
    return 'manual'
}

$Manager = Resolve-Manager

function Install-Winget {
    param([string]$Id, [string]$Name)
    # NÃO use $args: é variável automática do PowerShell e a atribuição é ignorada.
    $cliArgs = @('install', '--id', $Id, '--exact', '--source', 'winget', '--disable-interactivity')
    if ($Yes) { $cliArgs += @('--accept-package-agreements', '--accept-source-agreements', '--silent') }
    Write-Status 'INFO' "winget install $Id"
    if (-not $Apply) { return $true }
    & winget @cliArgs 2>&1 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
    return ($LASTEXITCODE -eq 0)
}

function Install-Choco {
    param([string]$Id, [string]$Name)
    $cliArgs = @('install', $Id, '-y')
    if (-not $Yes) { $cliArgs = @('install', $Id) }
    Write-Status 'INFO' "choco install $Id"
    if (-not $Apply) { return $true }
    & choco @cliArgs 2>&1 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
    return ($LASTEXITCODE -eq 0)
}

function Install-Pip {
    param([string]$Pkg)
    Write-Status 'INFO' "pip install --user $Pkg"
    if (-not $Apply) { return $true }
    & python -m pip install --user --upgrade $Pkg 2>&1 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
    return ($LASTEXITCODE -eq 0)
}

function Install-Manual {
    param([string]$Url, [string]$Name, [string]$Why)
    # ${Name} com chaves: "$Name:" o PowerShell leria como variável de drive.
    Write-Status 'WARN' "${Name}: instalação manual necessária"
    Write-Host "      fonte: $Url" -ForegroundColor DarkGray
    Write-Host "      motivo: $Why" -ForegroundColor DarkGray
    if ($Name -like 'binwalk*' -or $Name -like 'sasquatch*' -or $Name -like 'firmware-mod-kit*') {
        Write-Host "      atalho: scripts/bootstrap-wsl.sh --profile firmware" -ForegroundColor DarkGray
    }
    return $false
}

# ───────────────────────────────────────────────────────────────────────────
#  Execução
# ───────────────────────────────────────────────────────────────────────────

$perfis = @($Profile)
if ($perfis -contains 'all') {
    $perfis = @('core', 'static', 'dynamic', 'mobile', 'firmware', 'net', 'plugins')
}

Write-Banner 'UnboxRE — bootstrap (Windows)' ("perfis: " + ($perfis -join ', '))
Write-Host ("  modo:   " + $(if ($Apply) { 'APLICANDO (-Apply)' } else { 'dry-run (nada será instalado)' })) -ForegroundColor $(if ($Apply) { 'Yellow' } else { 'DarkGray' })
Write-Host ("  método: " + $Manager) -ForegroundColor DarkGray
Write-Host ("  raiz:   " + $root) -ForegroundColor DarkGray

if ($Manager -eq 'none') {
    Write-Host ''
    Write-Status 'FAIL' "gerenciador '$Method' não encontrado" 
    Write-Host '  Instale o winget (App Installer, via Microsoft Store) ou o Chocolatey:' -ForegroundColor Yellow
    Write-Host '    Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString("https://community.chocolatey.org/install.ps1"))' -ForegroundColor DarkGray
    exit 2
}

$selected = @($Catalog | Where-Object {
    $p = $_.Profiles
    (@($perfis | Where-Object { $p -contains $_ }).Count -gt 0)
})

$installed = @()
$skipped = @()
$manual = @()
$failed = @()

foreach ($tool in $selected) {
    $name = $tool.Name
    $probe = $tool.Probe

    if ($probe -and (Test-CommandExists $probe)) {
        Write-Status 'OK' "$name — já instalado ($probe)"
        $skipped += $name
        continue
    }

    Write-Host ''
    Write-Host ("── $name  [" + ($tool.Profiles -join ',') + "]") -ForegroundColor Cyan
    Write-Host ("   por quê: " + $tool.Why) -ForegroundColor DarkGray
    Write-Host ("   licença: " + $tool.License) -ForegroundColor DarkGray

    # Get-Field, não $tool.X: o catálogo omite campos de propósito ("não existe
    # no winget") e o StrictMode do common.ps1 trata ausência como erro.
    $wgId = Get-Field $tool 'Winget'
    $chId = Get-Field $tool 'Choco'
    $pipPk = Get-Field $tool 'Pip'
    $npmPk = Get-Field $tool 'Npm'
    $cargoPk = Get-Field $tool 'Cargo'

    $ok = $false
    if ($Manager -eq 'winget' -and $wgId) {
        $ok = Install-Winget -Id $wgId -Name $name
        if (-not $ok -and $chId -and (Test-CommandExists 'choco')) {
            Write-Status 'WARN' 'winget falhou; tentando choco'
            $ok = Install-Choco -Id $chId -Name $name
        }
    } elseif ($Manager -eq 'choco' -and $chId) {
        $ok = Install-Choco -Id $chId -Name $name
        if (-not $ok -and $wgId -and (Test-CommandExists 'winget')) {
            Write-Status 'WARN' 'choco falhou; tentando winget'
            $ok = Install-Winget -Id $wgId -Name $name
        }
    } elseif ($pipPk) {
        $ok = Install-Pip -Pkg $pipPk
    } elseif ($npmPk) {
        Write-Status 'INFO' "npm install -g $npmPk"
        if ($Apply) {
            & npm install -g $npmPk 2>&1 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
            $ok = ($LASTEXITCODE -eq 0)
        } else { $ok = $true }
    } elseif ($cargoPk) {
        Write-Status 'INFO' "cargo install $cargoPk"
        if ($Apply) {
            & cargo install $cargoPk 2>&1 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
            $ok = ($LASTEXITCODE -eq 0)
        } else { $ok = $true }
    } else {
        $ok = Install-Manual -Url $tool.Url -Name $name -Why $tool.Why
    }

    if ($ok) { $installed += $name } else { $manual += $name }
}

# ── Perfil "plugins": instala os plugins no x64dbg ──────────────────────────

if ($perfis -contains 'plugins') {
    Write-Host ''
    Write-Host '── Plugins do x64dbg' -ForegroundColor Cyan
    Write-Host '   delega para scripts/re-build.ps1, que compila o MCP server e copia' -ForegroundColor DarkGray
    Write-Host '   os .dp64/.dp32 para x64dbg/release/{x64,x32}/plugins/.' -ForegroundColor DarkGray

    $rebuild = Join-Path $PSScriptRoot 're-build.ps1'
    if (Test-PathExists $rebuild) {
        $rargs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $rebuild)
        if ($Apply) { $rargs += '-Apply' } else { $rargs += '-DryRun' }
        $rargs += '-SkipRea'
        & powershell @rargs
    } else {
        Write-Status 'FAIL' 're-build.ps1 ausente' 'confira scripts/'
    }
}

# ── Resumo ──────────────────────────────────────────────────────────────────

Write-Host ''
Write-Host ('─' * 68) -ForegroundColor DarkCyan
Write-Host ("  instalados: {0}   já presentes: {1}   pendentes/manual: {2}" -f $installed.Count, $skipped.Count, $manual.Count) -ForegroundColor White
if ($manual.Count -gt 0) {
    Write-Host ''
    Write-Host '  Exigem instalação manual (ou outro perfil/ambiente):' -ForegroundColor Yellow
    foreach ($m in $manual) { Write-Host ("    · $m") -ForegroundColor Yellow }
}
if (-not $Apply) {
    Write-Host ''
    Write-Host '  Isto foi um DRY-RUN. Rode de novo com -Apply para instalar.' -ForegroundColor Cyan
}
Write-Host ''
Write-Host '  Depois de instalar, revalide:' -ForegroundColor DarkGray
Write-Host '    .\scripts\health-check.ps1' -ForegroundColor DarkGray
Write-Host ''

exit 0

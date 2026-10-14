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
    fetch     baixa os NÚCLEO de terceiros (Ghidra, x64dbg, REA, x64dbg-MCP)
              via fetch-tools.ps1 — o passo que faz o clone limpo funcionar
    core      toolchain de build (JDK, Node, Zig, CMake, Ninja, Rust, Python)
    static    análise estática (radare2, DIE, YARA, capa, retoolkit)
    dynamic   análise dinâmica (Frida, Wireshark, mitmproxy, QEMU)
    mobile    Android (jadx, apktool, WSL/Ubuntu)
    firmware  firmware/IoT (binwalk, unblob — via WSL)
    net       rede (tshark, mitmproxy, fluxzy)
    plugins   instala os plugins no x64dbg (delega a re-build.ps1)
    all/full  todos os perfis acima (inclui fetch)

    Aliases mantidos para os nomes usados na documentação (docs/04-instalacao.md):
    formats → mobile + firmware; network → net; wsl → bootstrap-wsl.sh.

.PARAMETER Apply
    Executa de fato. Sem esta flag, é dry-run.

.PARAMETER DryRun
    Alias explícito de "sem -Apply". Existe para que a linha de comando
    documentada ("-DryRun") não divirja do script; o padrão já é dry-run.

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
    [ValidateSet('fetch', 'core', 'static', 'dynamic', 'mobile', 'firmware', 'net', 'plugins', 'formats', 'network', 'wsl', 'all', 'full')]
    [string[]]$Profile = @('core'),

    [switch]$Apply,
    [switch]$DryRun,
    [ValidateSet('auto', 'winget', 'choco', 'manual')]
    [string]$Method = 'auto',
    [switch]$Yes
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'lib\common.ps1')
$root = Get-RepoRoot

# -DryRun é o oposto de -Apply: garante o modo somente-plano mesmo se alguém
# passar os dois (a documentação usa -DryRun, o código usa -Apply).
if ($DryRun) { $Apply = $false }

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
    # Capstone é BIBLIOTECA: não tem comando próprio (o `cstool` não vem no pacote do pip),
    # então o probe é por MÓDULO Python (`PyModule`), não por comando. Ele é dependência de
    # `scripts/disasm-range.py` — sem ele o script sai 2 com instrução de instalação.
    @{ Name = 'Capstone'; Profiles = @('static'); PyModule = 'capstone'; Pip = 'capstone'; Url = 'https://www.capstone-engine.org/'
       Why = 'disassembler programático — scripts/disasm-range.py depende dele'; License = 'BSD-3' }
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
    # gflags NÃO tem pacote no winget (medido: `winget search "debugging tools"` → nada) e
    # o pacote do WinDbg não o traz. Sem ele, o mesmo trabalho é feito por
    # scripts/load-snaps.ps1 (escreve o MESMO bit de registro) + capture-debugprint.ps1.
    @{ Name = 'gflags (Debugging Tools for Windows)'; Probe = 'gflags'; Profiles = @('dynamic')
       Url = 'https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools'
       Why = 'loader snaps: ver a decisão do loader quando a imagem é recusada — alternativa: scripts/load-snaps.ps1'; License = 'proprietária (EULA Microsoft)' }

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

# Contrato dos instaladores: devolvem 'ok' (instalado AGORA), 'present' (já estava
# instalado — o probe não pegou, mas o gerenciador confirma) ou 'fail' (pendente/
# manual). Booleanos não bastam: o winget sinaliza "já instalado" com um CÓDIGO DE
# ERRO no exit code (medido nesta máquina: `winget install zig.zig` num Zig já
# instalado → -1978335189 / 0x8A15002B "no applicable upgrade"), então “sucesso” e
# “falhou” não são as duas únicas leituras — e tratar “já instalado” como falha
# fazia o bootstrap listar Zig/CMake/Ninja como pendentes numa máquina que os tem.
function Install-Winget {
    param([string]$Id, [string]$Name)
    # NÃO use $args: é variável automática do PowerShell e a atribuição é ignorada.
    $cliArgs = @('install', '--id', $Id, '--exact', '--source', 'winget', '--disable-interactivity')
    if ($Yes) { $cliArgs += @('--accept-package-agreements', '--accept-source-agreements', '--silent') }
    Write-Status 'INFO' "winget install $Id"
    if (-not $Apply) { return 'ok' }
    $out = & winget @cliArgs 2>&1
    $out | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
    if ($LASTEXITCODE -eq 0) { return 'ok' }
    # Códigos em que o winget "não teve trabalho", mas o pacote está instalado:
    #   -1978335189 = 0x8A15002B UPDATE_NOT_APPLICABLE
    #   -1978335135 = 0x8A150061 PACKAGE_ALREADY_INSTALLED
    if (@(-1978335189, -1978335135) -contains $LASTEXITCODE) {
        Write-Status 'OK' "${Name}: já instalado (winget)"
        return 'present'
    }
    # Rede de segurança textual: o exit code do winget muda entre versões.
    if (($out | Out-String) -match 'already installed') {
        Write-Status 'OK' "${Name}: já instalado (winget)"
        return 'present'
    }
    return 'fail'
}

function Install-Choco {
    param([string]$Id, [string]$Name)
    $cliArgs = @('install', $Id, '-y')
    if (-not $Yes) { $cliArgs = @('install', $Id) }
    Write-Status 'INFO' "choco install $Id"
    if (-not $Apply) { return 'ok' }
    & choco @cliArgs 2>&1 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
    if ($LASTEXITCODE -eq 0) { return 'ok' }
    if ($LASTEXITCODE -eq 1641 -or $LASTEXITCODE -eq 3010) { return 'ok' }   # instalado, reboot pendente
    return 'fail'
}

function Install-Pip {
    param([string]$Pkg)
    Write-Status 'INFO' "pip install --user $Pkg"
    if (-not $Apply) { return 'ok' }
    & python -m pip install --user --upgrade $Pkg 2>&1 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
    if ($LASTEXITCODE -eq 0) {
        return 'ok'
    }
    if ((& python -m pip show $Pkg 2>$null | Select-Object -First 1)) { return 'present' }
    return 'fail'
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
    return 'fail'
}

# ───────────────────────────────────────────────────────────────────────────
#  Execução
# ───────────────────────────────────────────────────────────────────────────

# Normaliza aliases da documentação para os perfis reais do script, para que
# `-Profile formats` (docs) e `-Profile mobile,firmware` (código) sejam a MESMA
# coisa. Sem isto a doc e o código divergem — exatamente o que o CI agora pega.
$perfis = @($Profile)
if (($perfis -contains 'all') -or ($perfis -contains 'full')) {
    $perfis = @('fetch', 'core', 'static', 'dynamic', 'mobile', 'firmware', 'net', 'plugins')
}
if ($perfis -contains 'formats') { $perfis = @($perfis | Where-Object { $_ -ne 'formats' }) + @('mobile', 'firmware') }
if ($perfis -contains 'network') { $perfis = @($perfis | Where-Object { $_ -ne 'network' }) + @('net') }

# `core` IMPLICA `fetch`. A doc promete isso (README §3, docs/04): "o perfil core
# roda o fetch antes", porque sem o núcleo de terceiros a toolchain não tem contra
# o que trabalhar. O código não fazia a implicação — um clone limpo recebia
# "toolchain ok" e continuava SEM ghidra/x64dbg/rea-main. Achado pelo teste de
# bootstrap a partir de máquina zerada (relatório da rodada).
if ($perfis -contains 'core') { $perfis = @('fetch') + $perfis }
$perfis = @($perfis | Select-Object -Unique)

# 'wsl' não é um perfil de winget: delega ao bootstrap-wsl.sh (Linux toolchain).
if ($perfis -contains 'wsl') {
    $perfis = @($perfis | Where-Object { $_ -ne 'wsl' })
    $wslScript = Join-Path $PSScriptRoot 'bootstrap-wsl.sh'
    Write-Host ''
    Write-Host '── Perfil wsl (Linux toolchain)' -ForegroundColor Cyan
    if (Test-PathExists $wslScript) {
        $distro = 'Ubuntu'
        Write-Host "   rode dentro do WSL:  wsl -d $distro -- bash $wslScript --apply" -ForegroundColor DarkGray
        Write-Host '   (o provisionamento Linux não pode ser feito de dentro do PowerShell)' -ForegroundColor DarkGray
    } else {
        Write-Status 'FAIL' 'bootstrap-wsl.sh ausente' 'confira scripts/'
    }
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

# ── Perfil "fetch": os NÚCLEO de terceiros que NÃO são redistribuídos ─────────
# Estes vêm do upstream (config/tools.json), não do winget. Rodam primeiro: sem
# eles, nada mais do toolkit tem contra o que trabalhar.
if ($perfis -contains 'fetch') {
    Write-Host ''
    Write-Host '── Núcleo de terceiros (fetch do upstream)' -ForegroundColor Cyan
    Write-Host '   Ghidra, x64dbg, REA, x64dbg-MCP — ver config/tools.json' -ForegroundColor DarkGray
    $fetch = Join-Path $PSScriptRoot 'fetch-tools.ps1'
    if (Test-PathExists $fetch) {
        $fargs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $fetch)
        if ($Apply) { $fargs += '-Apply' }
        & powershell @fargs
    } else {
        Write-Status 'FAIL' 'fetch-tools.ps1 ausente' 'confira scripts/'
    }
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
    $pyMod = Get-Field $tool 'PyModule'

    # Duas formas de "já está aqui": comando no PATH ou módulo Python importável
    # (bibliotecas como o Capstone não têm comando). Sem a segunda, o bootstrap diria
    # "instalando capstone" a cada execução numa máquina que já o tem.
    $byCmd = [bool]($probe -and (Test-CommandExists $probe))
    $byMod = [bool]($pyMod -and (Test-PythonModule $pyMod))

    if ($byCmd -or $byMod) {
        $how = $(if ($byCmd) { $probe } else { "módulo Python '$pyMod'" })
        Write-Status 'OK' "$name — já instalado ($how)"
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

    $state = 'fail'
    if ($Manager -eq 'winget' -and $wgId) {
        $state = Install-Winget -Id $wgId -Name $name
        if ($state -eq 'fail' -and $chId -and (Test-CommandExists 'choco')) {
            Write-Status 'WARN' 'winget falhou; tentando choco'
            $state = Install-Choco -Id $chId -Name $name
        }
    } elseif ($Manager -eq 'choco' -and $chId) {
        $state = Install-Choco -Id $chId -Name $name
        if ($state -eq 'fail' -and $wgId -and (Test-CommandExists 'winget')) {
            Write-Status 'WARN' 'choco falhou; tentando winget'
            $state = Install-Winget -Id $wgId -Name $name
        }
    } elseif ($pipPk) {
        $state = Install-Pip -Pkg $pipPk
    } elseif ($npmPk) {
        Write-Status 'INFO' "npm install -g $npmPk"
        if ($Apply) {
            & npm install -g $npmPk 2>&1 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
            $state = $(if ($LASTEXITCODE -eq 0) { 'ok' } else { 'fail' })
        } else { $state = 'ok' }
    } elseif ($cargoPk) {
        Write-Status 'INFO' "cargo install $cargoPk"
        if ($Apply) {
            & cargo install $cargoPk 2>&1 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
            $state = $(if ($LASTEXITCODE -eq 0) { 'ok' } else { 'fail' })
        } else { $state = 'ok' }
    } else {
        $state = Install-Manual -Url $tool.Url -Name $name -Why $tool.Why
    }

    # `present` é sucesso (a ferramenta existe), mas não foi ESTE script que a
    # instalou — vai para "já presentes" para o resumo não mentir.
    if ($state -eq 'ok') { $installed += $name }
    elseif ($state -eq 'present') { $skipped += $name }
    else { $manual += $name }
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

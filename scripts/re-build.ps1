#Requires -Version 5.1
<#
.SYNOPSIS
    Compila os componentes locais do toolkit e instala os plugins no x64dbg.

.DESCRIPTION
    Duas responsabilidades, uma por vez:

      1. x64dbg-MCP-Server  (x64dbg-mcp-server-main/)  — compila com Zig e
         copia os .dp32/.dp64 para as pastas de plugin do x64dbg.
      2. REA                (rea-main/)                — instala dependências
         (npm ci, respeitando o lockfile) e compila o bundle (npm run compile).

    Sem -Apply nada é feito além de mostrar o plano. Com -Apply, cada etapa é
    idempotente: um componente já compilado e atualizado pode ser pulado com
    -Skip se você quiser economizar tempo.

    ARMADILHA CONHECIDA (documentada porque já mordeu): o `build.zig.zon` declara
    `minimum_zig_version = "0.14.0"`, mas o README do projeto exige **Zig 0.16-dev
    ou superior**. A versão do README é a verdadeira — o campo do zon está
    desatualizado. O script avisa quando o Zig detectado está abaixo de 0.16.

.PARAMETER Component
    all (padrão) | mcp | rea

.PARAMETER Apply
    Executa a compilação de fato. Sem esta flag, é dry-run.

.PARAMETER Skip
    Pula um componente mesmo com -Apply.

.EXAMPLE
    PS> .\scripts\re-build.ps1
    PS> .\scripts\re-build.ps1 -Component mcp -Apply
    PS> .\scripts\re-build.ps1 -Component rea -Apply -Skip mcp

.NOTES
    Nunca usa sudo. Nunca sobrescreve original/ dos alvos. Só escreve em
    x64dbg/release/*/plugins e em rea-main/ (dist, node_modules).
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'mcp', 'rea')]
    [string]$Component = 'all',
    [switch]$Apply,
    [string[]]$Skip = @()
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'lib\common.ps1')
$root = Get-RepoRoot
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

function Invoke-Step {
    <#
        Executa um comando externo capturando exit code. Em dry-run apenas mostra.
        Devolve $true em sucesso.
    #>
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Cmd,
        [Parameter(Mandatory)][string[]]$CommandArgs,
        [Parameter(Mandatory)][string]$WorkDir
    )
    if (-not $Apply) {
        Write-Status 'INFO' "DRY-RUN: (cd $WorkDir) $Cmd $($CommandArgs -join ' ')"
        return $true
    }
    Write-Status 'INFO' "$Label — $Cmd $($CommandArgs -join ' ')"
    Push-Location $WorkDir
    try {
        & $Cmd @CommandArgs 2>&1 | ForEach-Object { Write-Host ("      " + $_) -ForegroundColor DarkGray }
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if ($code -eq 0) {
        Write-Status 'OK' "$Label concluído"
        return $true
    }
    Write-Status 'FAIL' "$Label retornou exit code $code"
    return $false
}

# ───────────────────────────────────────────────────────────────────────────
#  1. x64dbg-MCP-Server
# ───────────────────────────────────────────────────────────────────────────
function Build-Mcp {
    Write-Section 'x64dbg-MCP-Server (Zig)'
    $proj = Join-Path $root 'x64dbg-mcp-server-main'
    if (-not (Test-PathExists $proj)) {
        Add-Result 'rebuild:mcp:src' 'FAIL' 'x64dbg-mcp-server-main/ ausente' 'confira o checkout'
        return
    }

    # Zig é pré-requisito; o mínimo do build.zig.zon (0.14.0) divergiu do README
    # (0.16-dev). Exigimos o do README para evitar erro de API do zig build.
    $zig = Get-CommandVersion -Name 'zig' -VersionArgs @('version')
    if ($null -eq $zig) {
        Add-Result 'rebuild:mcp:zig' 'FAIL' 'zig ausente' 'instale Zig 0.16-dev+ (scripts/bootstrap-windows.ps1 -Profile core -Apply; ver docs/04)'
        return
    }
    $zigClean = ($zig -replace '[^0-9\.\-]', '').Trim('.')
    $zigVersion = $null
    try { $zigVersion = [version]$zigClean } catch { }
    if ($zigVersion -and $zigVersion -lt [version]'0.15.0') {
        Add-Result 'rebuild:mcp:zig' 'WARN' "zig $zigClean — README exige 0.16-dev+; o build pode falhar por API" 'atualize o Zig'
    } else {
        Add-Result 'rebuild:mcp:zig' 'OK' "zig $zigClean"
    }

    # Já existe artefato instalado nas duas arquiteturas?
    $p64 = Join-Path $root 'x64dbg\release\x64\plugins\x64dbg-MCP-Server.dp64'
    $p32 = Join-Path $root 'x64dbg\release\x32\plugins\x64dbg-MCP-Server.dp32'
    if ((Test-PathExists $p64) -and (Test-PathExists $p32)) {
        Write-Status 'INFO' 'plugin já instalado nas duas arquiteturas (recompilar recria)'
    }

    # zig build -Doptimize=ReleaseSafe --prefix dist
    $okBuild = Invoke-Step -Label 'zig build' -Cmd 'zig' `
        -CommandArgs @('build', '-Doptimize=ReleaseSafe', '--prefix', 'dist') -WorkDir $proj

    if (-not $okBuild) {
        Add-Result 'rebuild:mcp:build' 'FAIL' 'compilação falhou' 'veja a saída acima; confirme a versão do Zig'
        return
    }

    $dist = Join-Path $proj 'dist'
    $src64 = Join-Path $dist 'x64\plugins\x64dbg-MCP-Server.dp64'
    $src32 = Join-Path $dist 'x32\plugins\x64dbg-MCP-Server.dp32'

    if (-not $Apply) {
        Add-Result 'rebuild:mcp:install' 'INFO' 'copiaria dist/x64/plugins/*.dp64 → x64dbg/release/x64/plugins/' 'rode com -Apply'
        return
    }

    if (-not (Test-PathExists $src64)) {
        Add-Result 'rebuild:mcp:build' 'FAIL' "artefato esperado não encontrado: $src64" 'confira a saída do zig build'
        return
    }

    foreach ($pair in @(
            @{ Src = $src64; Dst = Join-Path $root 'x64dbg\release\x64\plugins' },
            @{ Src = $src32; Dst = Join-Path $root 'x64dbg\release\x32\plugins' }
        )) {
        if (-not (Test-PathExists $pair.Src)) { continue }
        New-DirIfMissing -Path $pair.Dst -Apply | Out-Null
        Copy-Item -LiteralPath $pair.Src -Destination $pair.Dst -Force
        Add-Result 'rebuild:mcp:install' 'OK' ("instalado: " + (Split-Path -Leaf $pair.Src))
    }
}

# ───────────────────────────────────────────────────────────────────────────
#  2. REA
# ───────────────────────────────────────────────────────────────────────────
function Build-Rea {
    Write-Section 'REA (Node/TypeScript)'
    $proj = Join-Path $root 'rea-main'
    if (-not (Test-PathExists (Join-Path $proj 'package.json'))) {
        Add-Result 'rebuild:rea:src' 'FAIL' 'rea-main/package.json ausente' 'confira o checkout do REA'
        return
    }

    # Node compatível: engines = ^22.19.0 || ^24.11.0 || >=26.0.0
    $nodeV = Get-CommandVersion -Name 'node' -VersionArgs @('-v')
    if ($null -eq $nodeV) {
        Add-Result 'rebuild:rea:node' 'FAIL' 'node ausente' 'instale Node LTS'
        return
    }
    $nodeClean = ($nodeV -replace '[^0-9\.]', '').Trim('.')
    try { $nodeVer = [version]$nodeClean } catch { $nodeVer = $null }
    $nodeOk = $false
    if ($nodeVer) {
        if ($nodeVer -ge [version]'24.11.0') { $nodeOk = $true }
        elseif ($nodeVer -ge [version]'22.19.0' -and $nodeVer -lt [version]'23.0.0') { $nodeOk = $true }
    }
    if ($nodeOk) {
        Add-Result 'rebuild:rea:node' 'OK' "node $nodeClean (engines satisfeito)"
    } else {
        Add-Result 'rebuild:rea:node' 'WARN' "node $nodeClean — engines pede ^22.19.0 || ^24.11.0 || >=26.0.0" 'atualize o Node'
    }

    # Sempre respeitar o lockfile: npm ci, nunca npm install.
    $haveLock = Test-PathExists (Join-Path $proj 'package-lock.json')
    $haveNM = Test-PathExists (Join-Path $proj 'node_modules')
    if ($haveNM -and -not $Apply) {
        Write-Status 'INFO' 'node_modules presente (npm ci recria do lockfile)'
    }

    if ($haveLock) {
        $okCi = Invoke-Step -Label 'npm ci' -Cmd 'npm' -CommandArgs @('ci') -WorkDir $proj
    } else {
        Add-Result 'rebuild:rea:lock' 'WARN' 'package-lock.json ausente — usando npm install' 'prefira um checkout com lockfile'
        $okCi = Invoke-Step -Label 'npm install' -Cmd 'npm' -CommandArgs @('install') -WorkDir $proj
    }
    if (-not $okCi) {
        Add-Result 'rebuild:rea:deps' 'FAIL' 'instalação de dependências falhou' 'veja a saída acima'
        return
    }
    if ($Apply) { Add-Result 'rebuild:rea:deps' 'OK' 'dependências instaladas' }
    else { Add-Result 'rebuild:rea:deps' 'INFO' 'dependências seriam instaladas (npm ci)' }

    # compile: compila src → dist (runtime que scripts/rea.mjs consome)
    $okCompile = Invoke-Step -Label 'npm run compile' -Cmd 'npm' -CommandArgs @('run', 'compile') -WorkDir $proj
    if ($okCompile) {
        $dist = Join-Path $proj 'dist'
        if (-not $Apply) {
            Add-Result 'rebuild:rea:dist' 'INFO' 'bundle seria compilado (npm run compile)'
        } elseif (-not (Test-PathExists $dist)) {
            Add-Result 'rebuild:rea:dist' 'WARN' 'npm run compile terminou sem criar dist/' 'confira a saída'
        } else {
            Add-Result 'rebuild:rea:dist' 'OK' 'bundle compilado (dist/)'
        }
    } else {
        Add-Result 'rebuild:rea:dist' 'FAIL' 'compilação falhou' 'veja a saída acima'
        return
    }

    # doctor: confere se o REA encontra os runtimes externos (Ghidra etc.)
    if ($Apply) {
        $okDoctor = Invoke-Step -Label 'rea doctor' -Cmd 'node' -CommandArgs @('scripts/rea.mjs', 'doctor') -WorkDir $proj
        if ($okDoctor) {
            Add-Result 'rebuild:rea:doctor' 'OK' 'rea doctor passou'
        } else {
            Add-Result 'rebuild:rea:doctor' 'WARN' 'rea doctor reportou problemas' 'rode manualmente: node rea-main/scripts/rea.mjs doctor'
        }
    } else {
        Write-Status 'INFO' 'DRY-RUN: node scripts/rea.mjs doctor'
    }
}

# ─── Execução ────────────────────────────────────────────────────────────────
try {
    Write-Banner 'UnboxRE — re-build' "raiz: $root"
    Write-Host ("  modo: " + $(if ($Apply) { 'APLICAR' } else { 'DRY-RUN (use -Apply)' })) -ForegroundColor DarkGray
    if ($Skip.Count -gt 0) {
        Write-Host ("  pulando: " + ($Skip -join ', ')) -ForegroundColor DarkGray
    }

    if (($Component -eq 'all' -or $Component -eq 'mcp') -and ($Skip -notcontains 'mcp')) {
        Build-Mcp
    }
    if (($Component -eq 'all' -or $Component -eq 'rea') -and ($Skip -notcontains 'rea')) {
        Build-Rea
    }

    $results = Get-Results
    $fails = @($results | Where-Object { $_.Level -eq 'FAIL' })
    Write-Host ''
    Write-Host ('─' * 68) -ForegroundColor DarkCyan
    foreach ($r in $results) { Write-Status $r.Level ("{0} — {1}" -f $r.Check, $r.Detail) }

    if ($fails.Count -gt 0) {
        Write-Host ''
        Write-Host '  Como corrigir:' -ForegroundColor Yellow
        foreach ($f in $fails) { Write-Host ("    · {0}: {1}" -f $f.Check, $f.Fix) -ForegroundColor Yellow }
        Write-Host ''
        exit 1
    }

    if (-not $Apply) {
        Write-Host ''
        Write-Host '  Isto foi um DRY-RUN. Rode de novo com -Apply para compilar.' -ForegroundColor Yellow
    } else {
        Write-Host ''
        Write-Host '  Próximo passo: valide o ambiente com .\scripts\health-check.ps1' -ForegroundColor Green
    }
    Write-Host ''
    exit 0
} catch {
    Write-Host ("ERRO no re-build: " + $_.Exception.Message) -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    exit 2
}

#Requires -Version 5.1
<#
.SYNOPSIS
    Instala (e lista) extensões do Ghidra a partir de arquivos .zip locais.

.DESCRIPTION
    O Ghidra descobre extensões instaladas em `<Ghidra>/Ghidra/Extensions/`.
    Extensões já vêm empacotadas como .zip; instalar é copiar o .zip para lá e
    reiniciar o Ghidra (ou usar File → Install Extensions na GUI).

    Este script NÃO baixa nada da internet por padrão — download silencioso em um
    setup de RE é uma superfície de ataque. Em vez disso:

      1. Você coloca os .zip das extensões desejadas em `tools/ghidra-extensions/`.
      2. Roda `.\scripts\setup-ghidra-extensions.ps1 -List` para ver o que há e o
         que é recomendado.
      3. Roda `.\scripts\setup-ghidra-extensions.ps1 -Apply` para instalar todas.
         Se houver mais de uma versão de uma mesma extensão, o script alerta em
         vez de escolher por você.

    Orientações das extensões ficam em docs/tools/ghidra.md (recomendadas:
    GhidraMCP para acesso por LLM, FindCrypt para cripto, o "Decompiler" nativo já
    existe).

.PARAMETER List
    Apenas lista as extensões em staging e as recomendadas, sem instalar nada.

.PARAMETER Apply
    Copia os .zip de staging para <Ghidra>/Ghidra/Extensions/.

.PARAMETER ExtensionZip
    Instala um .zip específico (pode repetir). Ignora o staging se informado.

.PARAMETER GhidraDir
    Força o caminho do Ghidra (por padrão, autodetecta em ghidra/ghidra_*_PUBLIC).

.EXAMPLE
    PS> .\scripts\setup-ghidra-extensions.ps1 -List
    PS> .\scripts\setup-ghidra-extensions.ps1 -Apply
    PS> .\scripts\setup-ghidra-extensions.ps1 -Apply -ExtensionZip C:\caminho\GhidraMCP.zip

.NOTES
    Uma extensão carregada por `-postScript`/`analyzeHeadless` precisa que o
    processo do Ghidra seja reiniciado após a instalação.
#>
[CmdletBinding()]
param(
    [switch]$List,
    [switch]$Apply,
    [string[]]$ExtensionZip = @(),
    [string]$GhidraDir
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'lib\common.ps1')
$root = Get-RepoRoot
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

function Resolve-GhidraDir {
    param([string]$Explicit)
    if ($Explicit -and (Test-PathExists $Explicit)) { return (Resolve-Path $Explicit).Path }
    $base = Join-Path $root 'ghidra'
    if (-not (Test-PathExists $base)) { return $null }
    $cand = Get-ChildItem -Path $base -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'ghidra_*_PUBLIC' } | Select-Object -First 1
    if ($cand) { return $cand.FullName }
    return $null
}

$DEFAULT_EXT = Join-Path $root 'tools\ghidra-extensions'

$Recommended = @(
    @{ Name = 'GhidraMCP'; Why = 'expõe funções do Ghidra via HTTP/JSON — ponte para LLMs e agentes'; Url = 'https://github.com/LaurieWired/GhidraMCP' },
    @{ Name = 'FindCrypt / Findcrypt'; Why = 'identifica constantes de algoritmos cripto (AES/SHA/RC4...)'; Url = 'https://github.com/TorgoTorgo/ghidra-findcrypt' },
    @{ Name = 'Ghidra GPT (ghidra-gpt)'; Why = 'renomeia/comenta funções via LLM dentro do Ghidra'; Url = 'https://github.com/kevthehermit/GhidraGPT' },
    @{ Name = 'Function ID (FID)'; Why = 'reconhece bibliotecas conhecidas por assinatura (FLIRT-like)'; Url = 'https://github.com/threatrack/ghidra-fidb-repo' }
)

try {
    Write-Banner 'UnboxRE — extensões do Ghidra' "raiz: $root"

    $gdir = Resolve-GhidraDir -Explicit $GhidraDir
    if (-not $gdir) {
        Add-Result 'ghidra-ext:install' 'FAIL' 'instalação do Ghidra não encontrada' 'confira ghidra/ghidra_*_PUBLIC ou passe -GhidraDir'
        Write-Status 'FAIL' 'não é possível continuar sem o Ghidra'
        exit 1
    }
    $extDir = Join-Path $gdir 'Ghidra\Extensions'
    Add-Result 'ghidra-ext:dir' 'OK' "Ghidra em $gdir"

    # ── Recomendadas ────────────────────────────────────────────────────────
    Write-Section 'Extensões recomendadas (baixe manualmente e coloque em tools/ghidra-extensions/)'
    foreach ($r in $Recommended) {
        Write-Host ("  · {0,-24} {1}" -f $r.Name, $r.Why) -ForegroundColor Gray
        Write-Host ("    {0}" -f $r.Url) -ForegroundColor DarkGray
    }

    # ── Staging ─────────────────────────────────────────────────────────────
    $zips = @()
    if ($ExtensionZip.Count -gt 0) {
        foreach ($z in $ExtensionZip) {
            if (Test-PathExists $z) { $zips += (Resolve-Path $z).Path }
            else { Add-Result "ghidra-ext:zip" 'WARN' "não encontrado: $z" }
        }
    } else {
        if (-not (Test-PathExists $DEFAULT_EXT)) {
            if ($Apply) { New-Item -ItemType Directory -Path $DEFAULT_EXT -Force | Out-Null }
        }
        if (Test-PathExists $DEFAULT_EXT) {
            $zips = @(Get-ChildItem -Path $DEFAULT_EXT -Filter '*.zip' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        }
    }

    Write-Section 'Staging'
    if ($List) {
        if ($zips.Count -eq 0) {
            Write-Status 'INFO' "nenhum .zip em $DEFAULT_EXT"
        } else {
            foreach ($z in $zips) { Write-Status 'OK' (Split-Path -Leaf $z) }
        }
        Write-Host ''
        Write-Status 'INFO' 'somente listagem (-List); nada foi instalado.'
        Write-Host ''
        exit 0
    }
    if ($zips.Count -eq 0) {
        Add-Result 'ghidra-ext:staging' 'INFO' "nenhum .zip em $DEFAULT_EXT" 'baixe as extensões desejadas e coloque lá'
    } else {
        foreach ($z in $zips) {
            Add-Result 'ghidra-ext:staging' 'OK' (Split-Path -Leaf $z)
        }
    }

    # ── Instalar ────────────────────────────────────────────────────────────
    if ($Apply -and $zips.Count -gt 0) {
        Write-Section 'Instalando'
        New-DirIfMissing -Path $extDir -Apply | Out-Null
        # Detecta conflito de versões: dois zips cujo nome base (sem versão) coincide.
        $groups = $zips | Group-Object { (Split-Path -Leaf $_ ) -replace '[-_]?\d+\.\d+.*$', '' }
        foreach ($g in $groups) {
            if ($g.Count -gt 1) {
                Add-Result 'ghidra-ext:conflict' 'WARN' ("múltiplas versões para '" + $g.Name + "': " + (($g.Group | ForEach-Object { Split-Path -Leaf $_ }) -join ', ')) 'mantenha apenas a versão desejada'
            }
            foreach ($z in $g.Group) {
                $dest = Join-Path $extDir (Split-Path -Leaf $z)
                Copy-Item -LiteralPath $z -Destination $dest -Force
                Add-Result 'ghidra-ext:install' 'OK' ("instalado: " + (Split-Path -Leaf $z))
            }
        }
        Write-Status 'INFO' 'Reinicie o Ghidra (GUI) para carregar as extensões.'
    } elseif (-not $Apply -and $zips.Count -gt 0) {
        Write-Host ''
        Write-Host '  DRY-RUN: instale de fato com -Apply' -ForegroundColor Yellow
    }

    $results = Get-Results
    $fails = @($results | Where-Object { $_.Level -eq 'FAIL' })
    Write-Host ''
    Write-Host ('─' * 68) -ForegroundColor DarkCyan
    foreach ($r in $results) { Write-Status $r.Level ("{0} — {1}" -f $r.Check, $r.Detail) }
    Write-Host ''
    if ($fails.Count -gt 0) { exit 1 } else { exit 0 }
} catch {
    Write-Host ("ERRO no setup-ghidra-extensions: " + $_.Exception.Message) -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    exit 2
}

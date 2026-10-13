#Requires -Version 5.1
<#
.SYNOPSIS
    Cria o esqueleto de um caso de análise em work/<slug>/.

.DESCRIPTION
    Padroniza a área de trabalho de um alvo, para que todo caso tenha os mesmos
    subdiretórios e um intake.md com procedência registrada. Se um binário for
    informado, ele é copiado para src/ e o hash SHA-256 é calculado — a
    identidade do alvo é a primeira evidência de qualquer análise.

    `work/` está fora do Git (ver .gitignore). Nada aqui vai para o GitHub.

.PARAMETER Name
    Slug do caso (kebab-case). Ex.: acme-cad-2026.4

.PARAMETER Target
    Caminho de um binário/artefato a copiar para src/.

.PARAMETER Origin
    De onde o alvo veio (site, licença adquirida, etc.). Vai para o intake.

.PARAMETER Purpose
    Finalidade declarada da análise. Vai para o intake.

.PARAMETER Force
    Recria os diretórios se o caso já existir (NÃO apaga conteúdo existente;
    apenas completa o que faltar).

.EXAMPLE
    PS> .\scripts\new-case.ps1 -Name acme-cad-2026.4 -Target C:\downloads\setup.exe -Origin "site do fabricante" -Purpose "análise competitiva"
    PS> .\scripts\new-case.ps1 -Name demo -Purpose "sandbox"

.NOTES
    Nunca modifica o binário original. A cópia em src/ é feita uma única vez e
    nunca sobrescrita sem -Force explícito.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    [string]$Target,
    [string]$Origin = '',
    [string]$Purpose = '',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\common.ps1')
$root = Get-RepoRoot
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

# Slug: minúsculas, sem espaços; o resto é responsabilidade do usuário, mas
# normalizamos para evitar caminhos inválidos no Windows.
$slug = ($Name.Trim().ToLower() -replace '[^a-z0-9\-\._]', '-') -replace '-{2,}', '-'
if ([string]::IsNullOrWhiteSpace($slug)) {
    Write-Host 'ERRO: -Name inválido.' -ForegroundColor Red
    exit 2
}

$caseDir = Join-Path $root (Join-Path 'work' $slug)
$subdirs = @('src', 'unpacked', 'notes', 'scripts', 'captures', 'evidence')

try {
    Write-Banner "UnboxRE — novo caso" "slug: $slug"

    if (Test-PathExists $caseDir) {
        if (-not $Force) {
            Write-Status 'WARN' "work/$slug já existe (use -Force para completar diretórios ausentes)"
        } else {
            Write-Status 'INFO' "work/$slug já existe — completando o que faltar"
        }
    }

    foreach ($d in $subdirs) {
        $p = Join-Path $caseDir $d
        $created = New-DirIfMissing -Path $p -Apply
        if ($created) { Add-Result "dir:$d" 'OK' "criado work/$slug/$d" }
        else { Add-Result "dir:$d" 'INFO' "já existia" }
    }

    # ── Copiar o alvo e calcular hash ───────────────────────────────────────
    $hash = $null
    $targetName = $null
    if ($Target) {
        if (-not (Test-PathExists $Target)) {
            Add-Result 'target' 'FAIL' "alvo não encontrado: $Target" 'confira o caminho'
        } else {
            $item = Get-Item -LiteralPath $Target
            $targetName = $item.Name
            $dest = Join-Path $caseDir ('src\' + $targetName)
            if (Test-PathExists $dest) {
                Add-Result 'target' 'INFO' "src/$targetName já existe — não sobrescrevi"
            } else {
                Copy-Item -LiteralPath $item.FullName -Destination $dest -Force
                Add-Result 'target' 'OK' "copiado para work/$slug/src/$targetName"
            }
            $hash = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
            $sizeMB = [math]::Round($item.Length / 1MB, 2)
            Add-Result 'target:sha256' 'OK' $hash
            Add-Result 'target:size' 'INFO' "$sizeMB MB"
        }
    } else {
        Add-Result 'target' 'INFO' "nenhum alvo informado; coloque o binário em work/$slug/src/"
    }

    # ── intake.md ───────────────────────────────────────────────────────────
    $intakePath = Join-Path $caseDir 'notes\intake.md'
    if (-not (Test-PathExists $intakePath) -or $Force) {
        $now = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $sha = if ($hash) { $hash } else { '(sem alvo)' }
        $tname = if ($targetName) { $targetName } else { '(sem alvo)' }
        $orig = if ($Origin) { $Origin } else { '(não informado)' }
        $purp = if ($Purpose) { $Purpose } else { '(não informado)' }
        $body = @"
# Caso: $slug

- **Criado em:** $now
- **Alvo:** $tname
- **SHA-256:** $sha
- **Origem:** $orig
- **Finalidade declarada:** $purp

## Procedência e autorização

Descreva como o alvo foi obtido, sob qual licença, e por que a análise é
legítima (ex.: análise competitiva de software adquirido, pesquisa de segurança
autorizada, alvo próprio). Isso protege o projeto e é exigido pelo repo.

## Objetivos

- [ ] Ex.: entender o mecanismo de licenciamento
- [ ] Ex.: mapear o formato de arquivo proprietário
- [ ] Ex.: identificar bibliotecas de terceiros

## Diário de análise

| Data | Ação | Ferramenta | Resultado | Evidência |
|------|------|-----------|-----------|-----------|
|      |      |           |           |           |

## Artefatos gerados

Anote aqui os arquivos em ``unpacked/``, ``captures/`` e ``reports/``.
"@
        Set-Content -LiteralPath $intakePath -Value $body -Encoding UTF8
        Add-Result 'intake' 'OK' "escrito work/$slug/notes/intake.md"
    } else {
        Add-Result 'intake' 'INFO' 'intake.md já existe — não sobrescrevi'
    }

    # ── evidence hash.json ──────────────────────────────────────────────────
    if ($hash) {
        $ts = Get-Date -Format 'yyyyMMdd'
        $evPath = Join-Path $caseDir "evidence\$ts-intake-001.json"
        $ev = [pscustomobject]@{
            case       = $slug
            timestamp  = (Get-Date).ToString('o')
            action     = 'intake'
            target     = $targetName
            sha256     = $hash
            origin     = $Origin
            purpose    = $Purpose
            tool       = 'scripts/new-case.ps1'
        }
        Write-JsonFile -Path $evPath -Object $ev -Apply
        Add-Result 'evidence' 'OK' "evidência: work/$slug/evidence/$(Split-Path -Leaf $evPath)"
    }

    Write-Host ''
    Write-Host ('─' * 68) -ForegroundColor DarkCyan
    foreach ($r in (Get-Results)) { Write-Status $r.Level ("{0} — {1}" -f $r.Check, $r.Detail) }
    Write-Host ''
    Write-Host "  Caso pronto: work/$slug/  (fora do Git — não será publicado)" -ForegroundColor Green
    Write-Host '  Próximo passo (ex.):' -ForegroundColor DarkGray
    Write-Host "    .\ghidra\ghidra_*\support\analyzeHeadless.bat work\$slug\ghidra-proj $slug -import work\$slug\src\<binario>" -ForegroundColor DarkGray
    Write-Host ''
    exit 0
} catch {
    Write-Host ("ERRO em new-case: " + $_.Exception.Message) -ForegroundColor Red
    exit 2
}

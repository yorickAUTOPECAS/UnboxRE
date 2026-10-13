#Requires -Version 5.1
<#
.SYNOPSIS
    Varre o repositório em busca de segredos e de arquivos que nunca devem ir ao Git.

.DESCRIPTION
    Pensado para rodar ANTES de um commit/push que publique o toolkit. Duas checagens:

      1. Conteúdo — procura padrões de credenciais (chaves AWS/GitHub/Slack/Google,
         chaves privadas PEM, atribuições genéricas de api_key/secret/token/bearer,
         tokens do x64dbg-MCP).
      2. Topologia — verifica se arquivos que o .gitignore deveria barrar estão
         presentes ou (em repo Git) rastreados: config/env/unboxre.env, binários
         em work/, node_modules/, dumps, etc.

    Não corrige nada — apenas reporta. Exit code 1 quando encontra achados.

.PARAMETER Path
    Raiz a varrer. Padrão: raiz do toolkit.

.PARAMETER Json
    Saída JSON (para CI).

.PARAMETER IncludeSamples
    Inclui também a varredura de work/ (amostras). Desligado por padrão: work/ é
    ignorado pelo Git, então não vaza.

.EXAMPLE
    PS> .\scripts\scan-secrets.ps1
    PS> .\scripts\scan-secrets.ps1 -Json | Out-File reports\secrets.json

.NOTES
    Falsos positivos são esperados em documentação que cita formatos de chave.
    O script marca cada achado com arquivo:linha para você julgar.
#>
[CmdletBinding()]
param(
    [string]$Path,
    [switch]$Json,
    [switch]$IncludeSamples
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'lib\common.ps1')
$root = if ($Path) { (Resolve-Path $Path).Path } else { Get-RepoRoot }
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

# Diretórios ignorados na varredura de conteúdo.
# Checkouts de terceiros ficam fora: têm os próprios segredos de teste/fixtures e o
# próprio CI. Aqui só interessam os arquivos que NÓS publicamos.
$SkipDirs = @('\.git\', '\node_modules\', '\dist\', '\build\', '\.turbo\', '\ghidra\',
              '\x64dbg\', '\x64dbg-mcp-server-main\', '\rea-main\', '\tools\', '\vendor\',
              '\zig-out\', '\.zig-cache\')
if (-not $IncludeSamples) { $SkipDirs += '\work\' }

# Arquivos considerados binários (por extensão) — não varremos conteúdo.
$BinaryExt = @('.exe','.dll','.so','.dylib','.bin','.o','.a','.lib','.pdb','.dp32','.dp64',
               '.png','.jpg','.jpeg','.gif','.ico','.pdf','.zip','.gz','.7z','.rar','.tar',
               '.wasm','.dex','.apk','.class','.jar','.pyc','.db','.sqlite')

# ── Padrões de segredo ───────────────────────────────────────────────────────
# Cada padrão: nome, regex, severidade. Regex ancorada o suficiente para não
# inundar de ruído, solta o bastante para pegar variações.
$Patterns = @(
    @{ Name = 'Chave privada PEM';        Severity = 'FAIL'; Regex = '-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----' },
    @{ Name = 'AWS Access Key ID';        Severity = 'FAIL'; Regex = '\bAKIA[0-9A-Z]{16}\b' },
    @{ Name = 'AWS Secret (atribuição)';  Severity = 'WARN'; Regex = '(?i)aws_secret_access_key\s*[=:]\s*["'']?[A-Za-z0-9/+=]{40}' },
    @{ Name = 'GitHub token';             Severity = 'FAIL'; Regex = '\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b' },
    @{ Name = 'Slack token';              Severity = 'FAIL'; Regex = '\bxox[baprs]-[A-Za-z0-9-]{10,}\b' },
    @{ Name = 'Google API key';           Severity = 'FAIL'; Regex = '\bAIza[0-9A-Za-z\-_]{35}\b' },
    @{ Name = 'Stripe key';               Severity = 'FAIL'; Regex = '\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,}\b' },
    @{ Name = 'OpenAI/Anthropic key';     Severity = 'FAIL'; Regex = '\b(sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9\-_]{20,})\b' },
    @{ Name = 'JWT';                      Severity = 'WARN'; Regex = '\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b' },
    @{ Name = 'Bearer token literal';     Severity = 'WARN'; Regex = '(?i)authorization\s*[=:]\s*["'']?Bearer\s+[A-Za-z0-9._\-]{16,}' },
    @{ Name = 'Atribuição api_key/secret'; Severity = 'WARN'; Regex = '(?i)\b(api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[=:]\s*["''][^"''\s]{12,}["'']' },
    @{ Name = 'x64dbg-MCP authToken';     Severity = 'FAIL'; Regex = '"authToken"\s*:\s*"[^"]{8,}"' }
)

function Test-Skipped {
    param([string]$FullPath)
    foreach ($s in $SkipDirs) {
        $norm = '\' + ($s.Trim('\')) + '\'
        if ($FullPath -like "*$norm*") { return $true }
    }
    return $false
}

function Get-ScannableFiles {
    Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            -not (Test-Skipped $_.FullName) -and
            ($BinaryExt -notcontains $_.Extension.ToLower()) -and
            $_.Length -lt 2MB
        }
}

# ── 1. Conteúdo ──────────────────────────────────────────────────────────────
$findings = New-Object System.Collections.ArrayList

foreach ($file in (Get-ScannableFiles)) {
    $text = $null
    try { $text = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop } catch { continue }
    if ([string]::IsNullOrEmpty($text)) { continue }

    $lines = $text -split "`r?`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        # Linhas que claramente citam o padrão (docs do próprio scanner) não contam.
        if ($line -match 'Regex\s*=' -or $line -match 'scan-secrets') { continue }
        foreach ($p in $Patterns) {
            if ($line -match $p.Regex) {
                $redacted = $line.Trim()
                if ($redacted.Length -gt 100) { $redacted = $redacted.Substring(0, 97) + '...' }
                $null = $findings.Add([pscustomobject]@{
                    File     = $file.FullName.Substring($root.Length).TrimStart('\')
                    Line     = $i + 1
                    Pattern  = $p.Name
                    Severity = $p.Severity
                    Excerpt  = $redacted
                })
            }
        }
    }
}

# ── 2. Topologia ─────────────────────────────────────────────────────────────
$topology = New-Object System.Collections.ArrayList
$mustNotExist = @(
    @{ Path = 'config\env\unboxre.env'; Why = 'contém caminhos/segredos locais — use o .example' },
    @{ Path = 'x64dbg\mcp_config.json';  Why = 'contém o authToken do x64dbg-MCP' }
)
foreach ($m in $mustNotExist) {
    $full = Join-Path $root $m.Path
    if (Test-PathExists $full) {
        # Só é problema se estiver rastreado pelo Git.
        $tracked = $false
        if (Test-PathExists (Join-Path $root '.git')) {
            try {
                $out = git -C $root ls-files --error-unmatch $m.Path 2>$null
                if ($LASTEXITCODE -eq 0) { $tracked = $true }
            } catch { }
        }
        $sev = if ($tracked) { 'FAIL' } else { 'WARN' }
        $note = if ($tracked) { 'RASTREADO pelo Git!' } else { 'presente localmente (não rastreado)' }
        $null = $topology.Add([pscustomobject]@{
            File = $m.Path; Severity = $sev; Detail = "$note — $($m.Why)"
        })
    }
}

# Amostras/binários eventualmente rastreados
if (Test-PathExists (Join-Path $root '.git')) {
    try {
        $tracked = git -C $root ls-files 2>$null
        foreach ($f in ($tracked -split "`n")) {
            $f = $f.Trim()
            if ([string]::IsNullOrEmpty($f)) { continue }
            $ext = [System.IO.Path]::GetExtension($f).ToLower()
            if ($BinaryExt -contains $ext) {
                $null = $topology.Add([pscustomobject]@{
                    File = $f; Severity = 'FAIL'; Detail = 'binário rastreado no Git — não deve ser publicado'
                })
            }
            if ($f -like 'work/*') {
                $null = $topology.Add([pscustomobject]@{
                    File = $f; Severity = 'FAIL'; Detail = 'arquivo de work/ rastreado — amostras não vão para o Git'
                })
            }
        }
    } catch { }
}

# ── Relatório ────────────────────────────────────────────────────────────────
$failCount = @($findings | Where-Object { $_.Severity -eq 'FAIL' }).Count +
             @($topology | Where-Object { $_.Severity -eq 'FAIL' }).Count
$warnCount = @($findings | Where-Object { $_.Severity -eq 'WARN' }).Count +
             @($topology | Where-Object { $_.Severity -eq 'WARN' }).Count

if ($Json) {
    $payload = [pscustomobject]@{
        generatedAt = (Get-Date).ToString('o')
        root        = $root
        summary     = [pscustomobject]@{ fail = $failCount; warn = $warnCount }
        findings    = $findings
        topology    = $topology
    }
    Write-Output ($payload | ConvertTo-Json -Depth 8)
    if ($failCount -gt 0) { exit 1 } else { exit 0 }
}

Write-Banner 'UnboxRE — scan de segredos' "raiz: $root"
Write-Host ("  arquivos varridos: " + @(Get-ScannableFiles).Count) -ForegroundColor DarkGray
if (-not $IncludeSamples) { Write-Host '  (work/ não incluído — use -IncludeSamples)' -ForegroundColor DarkGray }

Write-Section 'Conteúdo'
if ($findings.Count -eq 0) {
    Write-Status 'OK' 'nenhum padrão de segredo encontrado'
} else {
    foreach ($f in $findings) {
        Write-Status $f.Severity ("{0}:{1}  [{2}]  {3}" -f $f.File, $f.Line, $f.Pattern, $f.Excerpt)
    }
}

Write-Section 'Topologia'
if ($topology.Count -eq 0) {
    Write-Status 'OK' 'nenhum arquivo indevido detectado'
} else {
    foreach ($t in $topology) { Write-Status $t.Severity ("{0} — {1}" -f $t.File, $t.Detail) }
}

Write-Host ''
Write-Host ('─' * 68) -ForegroundColor DarkCyan
$color = if ($failCount -gt 0) { 'Red' } elseif ($warnCount -gt 0) { 'Yellow' } else { 'Green' }
Write-Host ("  FAIL: {0}   WARN: {1}" -f $failCount, $warnCount) -ForegroundColor $color
if ($failCount -gt 0) {
    Write-Host ''
    Write-Host '  NÃO publique antes de resolver os FAIL acima.' -ForegroundColor Red
}
Write-Host ''

if ($failCount -gt 0) { exit 1 } else { exit 0 }

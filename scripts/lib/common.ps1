#Requires -Version 5.1
<#
    scripts/lib/common.ps1 — helpers compartilhados.

    Compatibilidade: PowerShell 5.1 (o que existe no Windows por padrão) e 7+.
    NÃO use ternário (?:), ?? ou -and/-or encadeados com pipeline: são sintaxe 7+.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

# ─── Localização ────────────────────────────────────────────────────────────

# Resolvido uma vez, no momento em que este arquivo é carregado (dot-source).
# $PSScriptRoot aqui é sempre scripts/lib/, então ../.. é a raiz do toolkit.
$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Get-RepoRoot {
    <#  Raiz do toolkit, resolvida no load de scripts/lib/common.ps1.  #>
    return $script:RepoRoot
}

function Get-ToolPath {
    param([string]$Name)
    $root = Get-RepoRoot
    return (Join-Path $root $Name)
}

# ─── Coleta de resultados ───────────────────────────────────────────────────

$script:Results = New-Object System.Collections.ArrayList

function Add-Result {
    <#
        Registra um resultado de verificação.
        Level: OK | WARN | FAIL | INFO | SKIP
    #>
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('OK','WARN','FAIL','INFO','SKIP')][string]$Level,
        [string]$Detail = '',
        [string]$Fix = ''
    )
    $null = $script:Results.Add([pscustomobject]@{
        Check  = $Check
        Level  = $Level
        Detail = $Detail
        Fix    = $Fix
    })
}

function Get-Results {
    return $script:Results
}

function Reset-Results {
    $script:Results.Clear()
}

function Write-Status {
    param(
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )
    $color = 'Gray'
    switch ($Level) {
        'OK'   { $color = 'Green' }
        'WARN' { $color = 'Yellow' }
        'FAIL' { $color = 'Red' }
        'INFO' { $color = 'Cyan' }
        'SKIP' { $color = 'DarkGray' }
    }
    Write-Host ("  [{0,-4}] {1}" -f $Level, $Message) -ForegroundColor $color
}

# ─── Sondagem de ferramentas ────────────────────────────────────────────────

function Test-CommandExists {
    param([Parameter(Mandatory)][string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { return $false }
    return $true
}

function Get-CommandVersion {
    <#
        Tenta obter a versão de um executável sem assumir a flag.
        Retorna a primeira linha não vazia da saída, ou 'presente'.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$VersionArgs = @('--version')
    )
    if (-not (Test-CommandExists $Name)) { return $null }
    foreach ($flag in $VersionArgs) {
        try {
            $out = & $Name $flag 2>&1 | Where-Object { $_ -and "$_".Trim() -ne '' } | Select-Object -First 1
            if ($out) { return ("$out".Trim() -replace '\s+', ' ') }
        } catch { }
    }
    return 'presente'
}

function Get-Field {
    <#
        Acesso tolerante a campo ausente.

        Com Set-StrictMode -Version 2.0, `$hash.Chave` em uma hashtable que não
        tem a chave lança PropertyNotFoundException. Isso é desejável em código
        de produção e hostil em catálogos declarativos — onde a ausência do
        campo É a informação ("não existe no winget").
    #>
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $Default
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $Default
}

function Test-PathExists {
    param([Parameter(Mandatory)][string]$Path)
    return (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)
}

function New-DirIfMissing {
    <#
        Cria diretório (e pais) se não existir.
        Retorna $true se criou, $false se já existia.
        Respeita -WhatIf via $Apply.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Apply
    )
    if (Test-PathExists $Path) { return $false }
    if ($Apply) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    return $true
}

function Test-TcpPort {
    <#  Verifica se algo escuta em host:port. Timeout curto para não travar o health-check.  #>
    param(
        [string]$ComputerName = '127.0.0.1',
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 400
    )
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $ok = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $ok) { return $false }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Get-JsonFileSafe {
    <#  Lê JSON tolerando ausência/erro. Retorna $null em falha.  #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-PathExists $Path)) { return $null }
    try {
        return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Object,
        [switch]$Apply
    )
    if (-not $Apply) {
        Write-Status 'INFO' "DRY-RUN: escreveria $Path"
        return
    }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-PathExists $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $json = $Object | ConvertTo-Json -Depth 12
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
    Write-Status 'OK' "escrito: $Path"
}

# ─── Banner ─────────────────────────────────────────────────────────────────

function Write-Banner {
    param([Parameter(Mandatory)][string]$Title, [string]$Subtitle = '')
    $line = ('─' * 68)
    Write-Host ''
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host ("  " + $Title) -ForegroundColor White
    if ($Subtitle) { Write-Host ("  " + $Subtitle) -ForegroundColor DarkGray }
    Write-Host $line -ForegroundColor DarkCyan
}

function Write-Section {
    param([Parameter(Mandatory)][string]$Title)
    Write-Host ''
    Write-Host ("── " + $Title + " ") -ForegroundColor Cyan
}

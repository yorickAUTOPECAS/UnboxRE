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

function Test-PythonModule {
    <#
        Um MÓDULO Python é importável pelo `python` do PATH?

        Existe porque biblioteca não tem comando próprio: o Capstone é catalogado desde
        sempre e o probe por comando dizia "ausente" numa máquina onde o `pip install
        --user` já tinha rodado (medido no round 8.1: `capstone 5.0.7` importável e nenhum
        `cstool` no PATH). Sem isto o bootstrap reinstalava a cada execução e o resumo
        nunca ficava verdadeiro.

        Aceita SÓ o nome do módulo (regex) — o valor vem do catálogo, mas um dia pode vir
        de outro lugar, e `python -c` é execução de código: nada de espaço, `;` ou aspas.
    #>
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -notmatch '^[A-Za-z_][A-Za-z0-9_.]*$') { return $false }
    if (-not (Test-CommandExists 'python')) { return $false }
    & python -c "import $Name" 2>$null
    return ($LASTEXITCODE -eq 0)
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
    <#
        Caminho existe? Aceita $null/cadeia vazia e devolve $false em vez de explodir.
        Importa no bootstrap a partir de máquina ZERADA: quem descobre o caminho de uma
        ferramenta ausente (Resolve-GhidraHome, Resolve-JdkHome…) devolve vazio, e o
        chamador quer reportar FAIL, não um erro de binding do PowerShell. Foi o que
        aconteceu de verdade: com ghidra/ removido, health-check.ps1 morria na seção
        "Ferramentas do núcleo" (linha 247) em vez de listar o que falta.
    #>
    param([AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
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

# ─── Descoberta dos runtimes do núcleo (Ghidra/JDK) ─────────────────────────
#
# Estes dois caminhos são o atrito nº 1 da instalação: uma variável de ambiente
# obsoleta faz o REA falhar com erro obscuro. A descoberta mora aqui (e não no
# health-check) para que o bootstrap e o re-build usem exatamente a mesma regra.

function Resolve-GhidraHome {
    <#
        Caminho de uma instalação do Ghidra utilizável.
        Ordem: -Explicit, $env:GHIDRA_INSTALL_DIR (se válido), <raiz>/ghidra/ghidra_*_PUBLIC
        (maior versão primeiro).
        "Válida" = tem support/analyzeHeadless.bat. Retorna $null se nada servir.
    #>
    param(
        [string]$Explicit,
        [string]$Root = (Get-RepoRoot)
    )
    foreach ($cand in @($Explicit, $env:GHIDRA_INSTALL_DIR)) {
        if ($cand -and (Test-PathExists (Join-Path $cand 'support\analyzeHeadless.bat'))) {
            return $cand
        }
    }
    $base = Join-Path $Root 'ghidra'
    if (Test-PathExists $base) {
        $dirs = @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'ghidra_*_PUBLIC' } |
            Sort-Object -Descending -Property @{
                Expression = {
                    $m = [regex]::Match($_.Name, 'ghidra_([0-9]+(?:\.[0-9]+)*)')
                    if ($m.Success) { [version]$m.Groups[1].Value } else { [version]'0.0' }
                }
            })
        foreach ($d in $dirs) {
            if (Test-PathExists (Join-Path $d.FullName 'support\analyzeHeadless.bat')) {
                return $d.FullName
            }
        }
    }
    return $null
}

function Get-JdkMajorVersion {
    <#  Maior versão de um diretório de JDK pelo nome (jdk-21.0.12 → 21). 0 se ilegível.  #>
    param([Parameter(Mandatory)][string]$Path)
    $name = Split-Path -Leaf $Path
    $m = [regex]::Match($name, '[0-9]+')
    if ($m.Success) { return [int]$m.Value }
    return 0
}

function Resolve-JdkHome {
    <#
        JDK para o Ghidra e para o REA.

        Pin documentado (docs/04-instalacao.md): JDK 21 LTS. A fonte primária é
        <Ghidra>/Ghidra/application.properties — `application.java.min=21` e
        `application.java.max=` (sem teto), ou seja: 21 é a linha testada pelo
        fornecedor e o resto é "deve funcionar". Preferimos o pin; versões acima
        ficam como fallback.

        Ordem: candidatos com a MAJOR do pin → acima do pin → abaixo do pin.
        Retorna $null se nenhum candidato tem bin\java.exe.
    #>
    param(
        [string]$Root = (Get-RepoRoot),
        [int]$Pin = 21
    )
    $cands = New-Object System.Collections.ArrayList
    $null = $cands.Add($env:JAVA_HOME)
    foreach ($pattern in @('ghidra\jdk*', 'tools\jdk*', 'jdk*')) {
        $base = Join-Path $Root $pattern
        foreach ($d in @(Get-ChildItem -Path $base -Directory -ErrorAction SilentlyContinue)) {
            $null = $cands.Add($d.FullName)
        }
    }
    foreach ($base in @(
        (Join-Path $env:ProgramFiles 'Java'),
        (Join-Path $env:ProgramFiles 'Eclipse Adoptium'),
        (Join-Path $env:ProgramFiles 'Microsoft'),
        (Join-Path $env:ProgramFiles 'Amazon Corretto'),
        (Join-Path $env:ProgramFiles 'Zulu')
    )) {
        foreach ($d in @(Get-ChildItem -Path (Join-Path $base 'jdk*') -Directory -ErrorAction SilentlyContinue)) {
            $null = $cands.Add($d.FullName)
        }
    }

    $valid = @($cands | Where-Object { $_ -and (Test-PathExists (Join-Path $_ 'bin\java.exe')) })
    if ($valid.Count -eq 0) { return $null }

    $pinned = @($valid | Where-Object { (Get-JdkMajorVersion $_) -eq $Pin })
    if ($pinned.Count -gt 0) { return ($pinned | Sort-Object | Select-Object -First 1) }

    $above = @($valid | Where-Object { (Get-JdkMajorVersion $_) -gt $Pin })
    if ($above.Count -gt 0) {
        return ($above | Sort-Object -Descending -Property @{ Expression = { Get-JdkMajorVersion $_ } } | Select-Object -First 1)
    }
    return ($valid | Sort-Object -Descending -Property @{ Expression = { Get-JdkMajorVersion $_ } } | Select-Object -First 1)
}

function Set-EnvFileValue {
    <#
        Grava KEY=VALUE em um arquivo de ambiente estilo .env, preservando
        comentários e ordem. Substitui a primeira ocorrência ativa da chave;
        acrescenta no fim se ela não existir. Cria o arquivo se faltar.
        Retorna $true se escreveu.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Value,
        [switch]$Apply
    )
    if (-not $Apply) {
        Write-Status 'INFO' "DRY-RUN: $Key=$Value em $Path"
        return $false
    }
    $lines = @()
    if (Test-PathExists $Path) { $lines = @(Get-Content -LiteralPath $Path -Encoding UTF8) }
    $found = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match ('^\s*' + [regex]::Escape($Key) + '\s*=')) {
            $lines[$i] = "$Key=$Value"
            $found = $true
            break
        }
    }
    if (-not $found) { $lines += "$Key=$Value" }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-PathExists $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $lines -Encoding UTF8
    return $true
}

function Set-UserEnvVar {
    <#
        Persiste KEY=VALUE no ambiente do usuário (escopo User), para que a correção
        sobreviva à sessão atual. Sem isto o valor obsoleto volta na próxima janela:
        um processo não altera o ambiente do pai, mas o Windows mantém um bloco de
        ambiente do usuário que toda sessão nova herda.

        Só é chamado pelos caminhos corretivos (-Apply/-Fix-Paths). Confere a leitura
        de volta e retorna $true apenas quando o valor persistiu de fato.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value,
        [switch]$Apply
    )
    if (-not $Apply) {
        Write-Status 'INFO' "DRY-RUN: persistir $Name=$Value (escopo User)"
        return $false
    }
    try {
        [Environment]::SetEnvironmentVariable($Name, $Value, 'User')
    } catch {
        Write-Status 'WARN' "não foi possível persistir $Name no ambiente do usuário: $($_.Exception.Message)"
        return $false
    }
    return ([Environment]::GetEnvironmentVariable($Name, 'User') -eq $Value)
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

function Get-ToolManifest {
    <#
        Lê config/tools.json — a fonte de verdade dos NÚCLEO de terceiros.
        Retorna o objeto .tools (hashtable/PSCustomObject indexado por slug) ou
        $null se o arquivo faltar/for inválido. Consumido por fetch-tools.ps1,
        health-check.ps1 e check-consistency.mjs (que validam o mesmo contrato).
    #>
    param([string]$Path)
    if (-not $Path) { $Path = Join-Path (Get-RepoRoot) 'config\tools.json' }
    $doc = Get-JsonFileSafe -Path $Path
    if ($null -eq $doc) { return $null }
    return (Get-Field $doc 'tools')
}

function Resolve-X64dbgMcpConfig {
    <#
        Caminho do mcp_config.json do plugin x64dbg-MCP, ou $null se ainda não existe.

        O plugin grava o arquivo AO LADO do x64dbg.exe — release\x64\ para o
        debugger 64-bit, release\x32\ para o 32-bit — e NÃO na raiz x64dbg/.
        Descoberto rodando o plugin de verdade (auditoria 2026-10-13): health-check
        e gen-mcp-config procuravam na raiz e nunca encontravam o token. A raiz
        fica como fallback para layouts antigos.
    #>
    param([string]$Root = (Get-RepoRoot))
    foreach ($rel in @('x64dbg\release\x64\mcp_config.json', 'x64dbg\release\x32\mcp_config.json', 'x64dbg\mcp_config.json')) {
        $p = Join-Path $Root $rel
        if (Test-PathExists $p) { return $p }
    }
    return $null
}

function Test-ToolMarker {
    <#
        True quando o glob do campo install.marker do manifest casa algo em disco.
        Ex.: 'ghidra/*/support/analyzeHeadless.bat' → True se houver instalação.
        Um glob 'x64dbg/*.exe' não existe; o manifest usa caminhos reais.
    #>
    param(
        [Parameter(Mandatory)][string]$Marker,
        [string]$Root = (Get-RepoRoot)
    )
    $full = Join-Path $Root $Marker
    return [bool]@(Get-ChildItem -Path $full -ErrorAction SilentlyContinue | Select-Object -First 1)
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

function Test-UnboxQuiet {
    <#
        Contrato de silêncio: health-check.ps1 define $UnboxQuiet = $Json no escopo
        do script. Ler $script:UnboxQuiet direto quebra sob StrictMode quando o script
        que fez dot-source não declara a variável (era o caso de scan-secrets.ps1,
        que imprimia um erro de variável indefinida antes de cada seção).
    #>
    $v = Get-Variable -Name UnboxQuiet -Scope Script -ErrorAction SilentlyContinue
    if (-not $v) { return $false }
    return [bool]$v.Value
}

function Write-Banner {
    param([Parameter(Mandatory)][string]$Title, [string]$Subtitle = '')
    if (Test-UnboxQuiet) { return }   # ver contrato de -Json em health-check.sh
    $line = ('─' * 68)
    Write-Host ''
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host ("  " + $Title) -ForegroundColor White
    if ($Subtitle) { Write-Host ("  " + $Subtitle) -ForegroundColor DarkGray }
    Write-Host $line -ForegroundColor DarkCyan
}

function Write-Section {
    param([Parameter(Mandatory)][string]$Title)
    if (Test-UnboxQuiet) { return }
    Write-Host ''
    Write-Host ("── " + $Title + " ") -ForegroundColor Cyan
}

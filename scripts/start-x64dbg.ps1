#Requires -Version 5.1
<#
.SYNOPSIS
    Põe o x64dbg no ar (minimizado) para o plugin MCP ficar vivo, espera a porta
    responder e, com -Check, faz uma chamada MCP real de ponta a ponta.

.DESCRIPTION
    O servidor MCP do x64dbg-MCP vive DENTRO do processo do x64dbg: sem GUI
    aberta, a porta 9094 (x64) / 9095 (x32) não existe. Esse era o último passo
    manual do fluxo — o script o automatiza:

      1. se a porta já responde, NÃO abre uma segunda instância (conflito);
      2. senão inicia x64dbg/release/<arch>/x64dbg.exe minimizado e registra o
         PID em .cache/run/x64dbg-<arch>.pid;
      3. espera a porta aceitar conexão e o token aparecer em
         x64dbg/mcp_config.json (o plugin o gera no primeiro run);
      4. com -Check delega para scripts/mcp-x64dbg-smoke.mjs (initialize →
         tools/list → uma tool real de leitura) e propaga o código de saída.

    Não eleva privilégio e não fecha nada que não tenha aberto — use -Stop para
    encerrar o que este script subiu.

.PARAMETER Arch
    x64 (padrão) ou x32. Muda o executável e a porta padrão.

.PARAMETER Port
    Sobrescreve a porta padrão (9094/9095).

.PARAMETER TimeoutSec
    Quanto esperar a porta responder depois do launch. Padrão: 60.

.PARAMETER Check
    Depois de pronto, roda a chamada MCP real e propaga o resultado. O
    x64dbg-MCP aceita Bearer; o token vem de x64dbg/mcp_config.json (ou de
    $env:X64DBG_TOKEN).

.PARAMETER Stop
    Para o x64dbg registrado por este script. Com -All, para todo processo
    x64dbg.exe da sessão (o pidfile não é obrigatório nesse caso).

.PARAMETER Json
    Saída JSON (contrato para CI/agente).

.EXAMPLE
    PS> .\scripts\start-x64dbg.ps1 -Check
    PS> .\scripts\start-x64dbg.ps1 -Check -Json
    PS> .\scripts\start-x64dbg.ps1 -Stop

.NOTES
    Exit: 0 pronto (e, com -Check, o MCP respondeu) · 1 pronto mas o check
    falhou · 2 x64dbg ausente ou não subiu. Nunca usa sudo.
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'x32')][string]$Arch = 'x64',
    [int]$Port = 0,
    [int]$TimeoutSec = 60,
    [switch]$Check,
    [switch]$Stop,
    [switch]$All,
    [switch]$Json
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'lib\common.ps1')
$UnboxQuiet = [bool]$Json
$root = Get-RepoRoot
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

$effectivePort = if ($Port -gt 0) { $Port } elseif ($Arch -eq 'x64') { 9094 } else { 9095 }
$exe = Join-Path $root "x64dbg\release\$Arch\x64dbg.exe"
$pidFile = Join-Path $root ".cache\run\x64dbg-$Arch.pid"
$smoke = Join-Path $root 'scripts\mcp-x64dbg-smoke.mjs'

$report = [ordered]@{
    arch        = $Arch
    port        = $effectivePort
    exe         = $exe
    alreadyUp   = $false
    started     = $false
    pid         = 0
    ready       = $false
    tokenFile   = $null
    tokenFound  = $false
    check       = $null
}

function Get-RecordedPid {
    if (-not (Test-PathExists $pidFile)) { return 0 }
    $raw = Get-Content -LiteralPath $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1
    $v = 0
    if ([int]::TryParse("$raw".Trim(), [ref]$v)) { return $v }
    return 0
}

function Clear-RecordedPid {
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
}

# ─── -Stop ───────────────────────────────────────────────────────────────────
if ($Stop) {
    if ($All) {
        $procs = @(Get-Process -Name 'x64dbg' -ErrorAction SilentlyContinue)
        foreach ($p in $procs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
        Clear-RecordedPid
        Write-Status $(if ($procs.Count) { 'OK' } else { 'SKIP' }) "x64dbg parado (-All): $($procs.Count) processo(s)"
        $report.alreadyUp = $false
        if ($Json) { [pscustomobject]$report | ConvertTo-Json -Depth 6 }
        exit 0
    }
    $p = Get-RecordedPid
    if ($p -le 0) {
        Write-Status 'SKIP' 'nenhum PID registrado por este script (use -Stop -All para encerrar qualquer x64dbg)'
        if ($Json) { [pscustomobject]$report | ConvertTo-Json -Depth 6 }
        exit 0
    }
    $proc = Get-Process -Id $p -ErrorAction SilentlyContinue
    if ($proc -and $proc.ProcessName -like 'x64dbg*') {
        Stop-Process -Id $p -Force
        Clear-RecordedPid
        Write-Status 'OK' "x64dbg parado (PID $p)"
    } else {
        Clear-RecordedPid
        Write-Status 'SKIP' "PID $p registrado não é mais um x64dbg vivo"
    }
    if ($Json) { [pscustomobject]$report | ConvertTo-Json -Depth 6 }
    exit 0
}

# ─── Cabeçalho ───────────────────────────────────────────────────────────────
if (-not $Json) {
    Write-Banner 'UnboxRE — x64dbg + MCP ao vivo' ("arquitetura: $Arch  ·  porta: $effectivePort")
}

# ─── Já está no ar? ──────────────────────────────────────────────────────────
if (Test-TcpPort -Port $effectivePort) {
    $report.alreadyUp = $true
    $report.ready = $true
    Write-Status 'OK' "porta $effectivePort já responde — não vou abrir uma segunda instância"
} else {
    if (-not (Test-PathExists $exe)) {
        Write-Status 'FAIL' "x64dbg não encontrado: $exe — rode .\scripts\fetch-tools.ps1 -Tool x64dbg -Apply"
        if ($Json) { [pscustomobject]$report | ConvertTo-Json -Depth 6 }
        exit 2
    }
    $runDir = Split-Path -Parent $pidFile
    New-DirIfMissing -Path $runDir -Apply | Out-Null

    Write-Status 'INFO' "iniciando $exe (minimizado)"
    $proc = Start-Process -FilePath $exe -WindowStyle Minimized -PassThru
    $report.started = $true
    $report.pid = $proc.Id
    Set-Content -LiteralPath $pidFile -Value $proc.Id -Encoding ASCII

    # O plugin sobe o servidor durante o startup; a porta é o sinal de pronto.
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $readyPort = $false
    while ((Get-Date) -lt $deadline) {
        if ($proc.HasExited) { break }
        if (Test-TcpPort -Port $effectivePort) { $readyPort = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $readyPort) {
        if ($proc.HasExited) {
            Write-Status 'FAIL' "x64dbg saiu durante o startup (exit $($proc.ExitCode)) — confirme os arquivos em x64dbg/release"
        } else {
            Write-Status 'FAIL' "porta $effectivePort não respondeu em ${TimeoutSec}s — o plugin pode não ter carregado (x64dbg/release/*/plugins)"
        }
        if ($Json) { [pscustomobject]$report | ConvertTo-Json -Depth 6 }
        exit 2
    }
    $report.ready = $true
    Write-Status 'OK' "porta $effectivePort respondendo (PID $($proc.Id))"

    # Minimiza de fato (Start-Process -WindowStyle nem todo app honra).
    try {
        if ($proc.MainWindowHandle -ne 0) {
            Add-Type -Namespace UnboxRE -Name Win32 -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);' -ErrorAction SilentlyContinue
            [UnboxRE.Win32]::ShowWindow($proc.MainWindowHandle, 6) | Out-Null
        }
    } catch { }
}

# ─── Token (o plugin grava ao lado do x64dbg.exe, não na raiz) ───────────────
$tokenDeadline = (Get-Date).AddSeconds(15)
$tokenPath = $null
while (-not $tokenPath -and (Get-Date) -lt $tokenDeadline) {
    $tokenPath = Resolve-X64dbgMcpConfig
    if (-not $tokenPath) { Start-Sleep -Milliseconds 300 }
}
if ($tokenPath) {
    $report.tokenFound = $true
    $report.tokenFile = $tokenPath
    Write-Status 'OK' "token do plugin: $tokenPath"
} else {
    Write-Status 'WARN' 'token ainda não existe (x64dbg/release/{x64,x32}/mcp_config.json) — o plugin grava no primeiro run'
}

# ─── Check MCP real ──────────────────────────────────────────────────────────
if ($Check) {
    if (-not (Test-PathExists $smoke)) {
        Write-Status 'FAIL' "smoke MCP ausente: $smoke"
        $report.check = @{ ran = $false; ok = $false; reason = 'smoke ausente' }
        if ($Json) { [pscustomobject]$report | ConvertTo-Json -Depth 6 }
        exit 1
    }
    Write-Status 'INFO' "rodando a chamada MCP real (node scripts/mcp-x64dbg-smoke.mjs --port $effectivePort)"
    $checkOut = & node $smoke --port $effectivePort
    $code = $LASTEXITCODE
    if (-not $Json) { $checkOut | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray } }
    $report.check = @{ ran = $true; ok = ($code -eq 0); exitCode = $code }
    if ($code -ne 0) {
        if ($Json) { [pscustomobject]$report | ConvertTo-Json -Depth 6 }
        exit 1
    }
}

if ($Json) { [pscustomobject]$report | ConvertTo-Json -Depth 6 }
exit 0

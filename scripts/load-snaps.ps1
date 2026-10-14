#Requires -Version 5.1
<#
.SYNOPSIS
    Liga/desliga "loader snaps" (FLG_SHOW_LDR_SNAPS) para um binário — o efeito de
    `gflags /i app.exe +sls`, sem depender do gflags.exe.

.DESCRIPTION
    Um binário que morre antes de chegar ao entrypoint (0xC000007B, 0xC0000135,
    0xC0000142…) não deixa rastro próprio: quem o rejeita é o LOADER, dentro do ntdll.
    "Loader snaps" faz o loader imprimir cada passo (imagem, imports, relocações,
    dependências) na saída de depuração — é a única forma documentada de ver a decisão
    que recusou a imagem.

    O gflags.exe (Debugging Tools for Windows, dentro do Windows SDK) é a ferramenta
    canônica para isso, mas ele NÃO acompanha o WinDbg moderno do winget (medido nesta
    máquina: o pacote Microsoft.WinDbg 1.2610.1001.0 não tem gflags.exe) e não existe
    pacote winget só dos Debugging Tools. O que o `gflags /i` faz é escrever um bit no
    registro — FLG_SHOW_LDR_SNAPS = 0x02 — na chave de Image File Execution Options da
    imagem. Este script faz exatamente essa escrita, de forma auditável e reversível.

    Chave: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<imagem>
    Valor: GlobalFlag (DWORD). `+sls` liga o bit 0x2; `-sls` desliga.

    Vale para INSTÂNCIAS NOVAS do processo (não pega um processo já rodando) e a saída
    só aparece com um debugger anexado ao processo novo — no nosso fluxo, o x64dbg
    (`StartScylla`/LoadBinary) e `scripts/x64dbg-drive.mjs --call 'GetEventLog {"count":N}'`.

    Escrita em HKLM exige ELEVAÇÃO. Este script NUNCA se eleva sozinho: sem -Apply ele
    só mostra o plano (dry-run), e com -Apply fora de um shell elevado ele para com
    instrução clara. Abra um PowerShell elevado e rode de novo.

.PARAMETER Image
    Nome do arquivo (com extensão), como o gflags usa: `alvo.exe`. Não é caminho.

.PARAMETER Apply
    Executa a escrita/remoção. Sem ele, o script só mostra o que faria (dry-run).

.PARAMETER Disable
    Desliga o flag (equivalente a `gflags /i alvo.exe -sls`) em vez de ligar.

.PARAMETER Status
    Só lê e mostra o estado atual do GlobalFlag da imagem (nenhuma escrita).

.PARAMETER Json
    Emite o resultado em JSON.

.EXAMPLE
    PS> .\scripts\load-snaps.ps1 -Image dump-fixed.exe            # dry-run: mostra o plano
    PS> .\scripts\load-snaps.ps1 -Image dump-fixed.exe -Status
    PS> .\scripts\load-snaps.ps1 -Image dump-fixed.exe -Apply     # em shell ELEVADO
    PS> .\scripts\load-snaps.ps1 -Image dump-fixed.exe -Disable -Apply

.NOTES
    Exit code: 0 = plano/estado lido (ou escrita feita) · 1 = escrita recusada (sem
    elevação) · 2 = erro de uso. Nunca usa sudo/elevação automática.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Image,
    [switch]$Apply,
    [switch]$Disable,
    [switch]$Status,
    [switch]$Json
)

. (Join-Path $PSScriptRoot 'lib\common.ps1')

$ErrorActionPreference = 'Stop'
$FLG_SHOW_LDR_SNAPS = 0x2
$KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$Image"

function Test-Elevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CurrentFlag {
    if (-not (Test-PathExists -Path $KeyPath)) { return $null }
    $v = Get-ItemProperty -Path $KeyPath -Name GlobalFlag -ErrorAction SilentlyContinue
    # StrictMode: não acesse a propriedade direto (chave existe sem o valor é o caso normal)
    if ($null -eq $v -or -not $v.PSObject.Properties['GlobalFlag']) { return 0 }
    return [int]$v.GlobalFlag
}

$current = Get-CurrentFlag
$desired = $current
$action = 'status'

if (-not $Status) {
    if ($Disable) {
        $desired = if ($null -eq $current) { 0 } else { $current -band (-bnot $FLG_SHOW_LDR_SNAPS) }
        $action = 'disable'
    } else {
        $desired = if ($null -eq $current) { $FLG_SHOW_LDR_SNAPS } else { $current -bor $FLG_SHOW_LDR_SNAPS }
        $action = 'enable'
    }
}

$slsOn = ($null -ne $current) -and (($current -band $FLG_SHOW_LDR_SNAPS) -ne 0)
$result = [ordered]@{
    image      = $Image
    key        = $KeyPath
    action     = if ($Status) { 'status' } else { $action }
    applied    = $false
    dryRun     = (-not $Apply) -and (-not $Status)
    keyExists  = (Test-PathExists -Path $KeyPath)
    globalFlag = if ($null -eq $current) { $null } else { "0x{0:X}" -f $current }
    loaderSnaps = $slsOn
    desiredFlag = if ($Status) { $null } else { "0x{0:X}" -f $desired }
    elevated   = Test-Elevated
}

if ($Status) {
    if ($Json) { $result | ConvertTo-Json -Depth 4 }
    else {
        Write-Status -Level 'INFO' -Message "imagem: $Image"
        Write-Status -Level 'INFO' -Message "chave: $KeyPath ($(if ($result.keyExists) { 'existe' } else { 'não existe' }))"
        Write-Status -Level $(if ($slsOn) { 'OK' } else { 'SKIP' }) -Message "GlobalFlag = $(if ($null -eq $current) { '<ausente>' } else { $result.globalFlag })$(if ($slsOn) { '  (FLG_SHOW_LDR_SNAPS ligado)' } else { '  (loader snaps desligado)' })"
    }
    exit 0
}

if (-not $Apply) {
    if ($Json) { $result | ConvertTo-Json -Depth 4 }
    else {
        Write-Status -Level 'INFO' -Message "DRY-RUN (nada foi escrito). O plano:"
        $efeito = 'ligar loader snaps (FLG_SHOW_LDR_SNAPS=0x2)'
        if ($Disable) { $efeito = 'desligar loader snaps' }
        Write-Status -Level 'INFO' -Message "  chave alvo : $KeyPath"
        Write-Status -Level 'INFO' -Message "  GlobalFlag : $(if ($null -eq $current) { '<ausente>' } else { $result.globalFlag }) -> 0x$("{0:X}" -f $desired)"
        Write-Status -Level 'INFO' -Message "  efeito     : $efeito"
        Write-Status -Level 'INFO' -Message "  depois     : rode com -Apply em um PowerShell ELEVADO (HKLM exige admin)"
        Write-Status -Level 'INFO' -Message '  ler a saída: debugger anexado ao processo NOVO (x64dbg + scripts/x64dbg-drive.mjs --call GetEventLog)'
        Write-Status -Level 'INFO' -Message '  as linhas do loader chegam no log do debugger; capture com --json para virar evidência'
    }
    exit 0
}

if (-not (Test-Elevated)) {
    if ($Json) {
        $result['error'] = 'sem elevação'
        $result | ConvertTo-Json -Depth 4
    } else {
        Write-Status -Level 'FAIL' -Message "HKLM exige elevação — este script não se eleva sozinho."
        Write-Status -Level 'INFO' -Message "abra um PowerShell COMO ADMINISTRADOR e rode:"
        Write-Status -Level 'INFO' -Message "  .\scripts\load-snaps.ps1 -Image $Image $(if ($Disable) { '-Disable ' }) -Apply"
    }
    exit 1
}

if (-not (Test-PathExists -Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
if ($desired -eq 0 -and (Test-PathExists -Path $KeyPath)) {
    # 0 = nenhum flag: não deixe um valor morto na chave (foi o gflags que escreveu? apague)
    Remove-ItemProperty -Path $KeyPath -Name GlobalFlag -ErrorAction SilentlyContinue
} else {
    New-ItemProperty -Path $KeyPath -Name GlobalFlag -PropertyType DWord -Value $desired -Force | Out-Null
}
$result.applied = $true
$result.globalFlag = "0x{0:X}" -f (Get-CurrentFlag)

if ($Json) { $result | ConvertTo-Json -Depth 4 }
else {
    Write-Status -Level 'OK' -Message "GlobalFlag de ${Image} agora é $($result.globalFlag) (chave: $KeyPath)"
    if ($action -eq 'enable') {
        Write-Status -Level 'INFO' -Message "loader snaps LIGADOS — a saída aparece no debugger do processo NOVO, não aqui."
    } else {
        Write-Status -Level 'INFO' -Message "loader snaps desligados (nada mais é impresso pelo loader)."
    }
}
exit 0

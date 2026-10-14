#Requires -Version 5.1
<#
.SYNOPSIS
    Captura a saída de depuração do sistema (OutputDebugString/DbgPrint) por alguns
    segundos — é assim que se LÊ o loader snaps ligado por load-snaps.ps1.

.DESCRIPTION
    Quem escreve "loader snaps" é o loader do Windows (ntdll), via a saída de depuração.
    A documentação da Microsoft descreve dois destinos:

      * se o processo NOVO tem um debugger, a saída vai para o debugger (x64dbg, WinDbg);
      * se não tem, ela deveria ir para o canal global `DBWIN_BUFFER`, que qualquer
        listener lê.

    MEDIDO NESTA MÁQUINA (2026-10-14), e o segundo caso NÃO se confirmou: com o flag ligado
    e sem debugger, nem uma imagem válida (`clean.exe`, que carrega 50 DLLs) produziu
    qualquer byte aqui — enquanto um `OutputDebugString` direto de outro processo FOI
    capturado pelo mesmo listener (auto-teste em trabalho/iat-hardcase/evidence/
    20261014-13-dbwin-selftest.txt). Conclusão prática: para ler loader snaps, use um
    debugger (janela Log do x64dbg / WinDbg). Este script continua sendo o leitor certo do
    canal global para `OutputDebugString` de alvos que não estão sob debugger.

    `scripts/load-snaps.ps1` liga o flag; este script é o listener. Os dois juntos
    respondem "por que o loader recusou ESTA imagem?" sem depender de DebugView nem de
    GUI — o que importa para um fluxo que tem de ser auditável por comando.

    O listener precisa começar ANTES do processo alvo (senão perde as primeiras linhas).
    Este script inicia o listener, espera o tempo pedido e grava o que chegou.

    Não é preciso elevação: ler o canal global é permitido a qualquer usuário.

.PARAMETER Seconds
    Por quanto tempo escutar (default 15). O processo alvo deve ser iniciado nessa janela.

.PARAMETER OutFile
    Arquivo de saída (texto). Sem ele, imprime na tela.

.PARAMETER Filter
    Só grava linhas que contenham este texto (ex.: `LDR:`). Default: tudo.

.EXAMPLE
    PS> .\scripts\capture-debugprint.ps1 -Seconds 20 -OutFile work\alvo\evidence\loadsnaps.txt
    # (em outra janela, nos 20 s seguintes)
    PS> .\work\alvo\unpacked\dump-fixed.exe

.NOTES
    Exit code: 0 = escutou até o fim · 2 = erro de uso. Nunca usa sudo.
#>
[CmdletBinding()]
param(
    [int]$Seconds = 15,
    [string]$OutFile,
    [string]$Filter = ''
)

. (Join-Path $PSScriptRoot 'lib\common.ps1')

$ErrorActionPreference = 'Stop'
if ($Seconds -lt 1 -or $Seconds -gt 600) {
    Write-Status -Level 'FAIL' -Message '-Seconds precisa estar entre 1 e 600'
    exit 2
}

# Listener minimalista do canal DBWIN (o mesmo que o DebugView usa). A API é velha e
# estável: mapeamento "DBWIN_BUFFER" (4 bytes de PID + a string) e dois eventos.
$src = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public class DbgWin {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateFileMapping(IntPtr h, IntPtr sa, uint prot, uint hi, uint lo, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr MapViewOfFile(IntPtr h, uint access, uint hi, uint lo, UIntPtr size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateEvent(IntPtr sa, bool manual, bool initial, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetEvent(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);

    public static void Listen(int seconds, string outFile, string filter) {
        IntPtr bufferReady = CreateEvent(IntPtr.Zero, false, false, "DBWIN_BUFFER_READY");
        IntPtr dataReady   = CreateEvent(IntPtr.Zero, false, false, "DBWIN_DATA_READY");
        IntPtr mapping     = CreateFileMapping(new IntPtr(-1), IntPtr.Zero, 0x04, 0, 4096, "DBWIN_BUFFER");
        IntPtr view        = MapViewOfFile(mapping, 0x04, 0, 0, new UIntPtr(4096));
        if (bufferReady == IntPtr.Zero || dataReady == IntPtr.Zero || view == IntPtr.Zero)
            throw new Exception("nao consegui abrir o canal DBWIN_BUFFER");

        StreamWriter w = outFile == null ? null : new StreamWriter(outFile, false, new UTF8Encoding(false));
        DateTime deadline = DateTime.UtcNow.AddSeconds(seconds);
        try {
            while (DateTime.UtcNow < deadline) {
                SetEvent(bufferReady);
                uint left = (uint)Math.Max(1, (deadline - DateTime.UtcNow).TotalMilliseconds);
                if (WaitForSingleObject(dataReady, Math.Min(left, 500)) != 0) continue;
                int pid = Marshal.ReadInt32(view);
                string msg = Marshal.PtrToStringAnsi(new IntPtr(view.ToInt64() + 4));
                if (msg == null) continue;
                msg = msg.TrimEnd('\r', '\n');
                if (filter != null && filter.Length > 0 && msg.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) continue;
                string line = "[pid " + pid + "] " + msg;
                Console.WriteLine(line);
                if (w != null) { w.WriteLine(line); w.Flush(); }
            }
        } finally {
            if (w != null) w.Dispose();
        }
    }
}
'@
Add-Type -TypeDefinition $src -Language CSharp

$out = if ($OutFile) { $OutFile } else { $null }
if ($out) {
    $dir = Split-Path -Parent $out
    if ($dir) { New-DirIfMissing -Path $dir | Out-Null }
}
Write-Status -Level 'INFO' -Message "escutando a saída de depuração por ${Seconds}s — inicie o processo alvo AGORA"
if ($Filter) { Write-Status -Level 'INFO' -Message "filtro: '$Filter'" }
[DbgWin]::Listen($Seconds, $out, $Filter)
if ($out) { Write-Status -Level 'OK' -Message "gravado em $out" } else { Write-Status -Level 'OK' -Message 'fim da escuta' }
exit 0

# park-patch-run.ps1 — parkeia o alvo no prompt, aplica PATCHES DE CODIGO em memoria, alimenta a
# entrada e captura a saida (round 8.5).
#
# Por que existe: o caminho pos-entrada do alvo dura <1 ms (medido: NtSuspendProcess devolve
# 0xC000010A = STATUS_PROCESS_IS_TERMINATING ate com atraso 0). A unica forma determinista de ler o
# que ele calcula e instrumentar em memoria ENQUANTO ele esta parado esperando a senha.
# Aqui o patch e de codigo (RVA=bytes), que serve para qualquer coisa: trocar um imediato, forcar um
# retorno, desviar um salto. Nada e escrito no ARQUIVO; o alvo original fica intacto.
#
# Uso:
#   powershell -File .../park-patch-run.ps1 -Target <exe> -Entrada 'CMO{...}' \
#       -Patch '0x7fe0=48b82e90ad62fdad8f2ac3' -EsperaSaidaMs 3000
# park-patch-run.ps1 — instrui um alvo VIVO: parkeia no prompt, aplica patches de codigo em
# memoria, alimenta a entrada, deixa o alvo congelado (IAT em `jmp $`) e LE o que ele calculou.
#
# Por que existe: quando o caminho pos-entrada dura <1 ms (medido: NtSuspendProcess devolve
# 0xC000010A = STATUS_PROCESS_IS_TERMINATING ate com atraso 0), a unica forma determinista de ler
# o que o alvo calcula e instrumentar em memoria ENQUANTO ele espera a entrada. Foi o que resolveu
# o alvo `nivel 5` da rodada 8.5 — sem o instrumento, o alvo "nao tinha saida" para observar.
# Nada e escrito no ARQUIVO: o alvo original fica intacto (patch so na copia em memoria).
#
# Modos:
#   -Patch 'rva=hex'          troca bytes (imediato, prologo, salto) — o patch mais simples
#   -FreezeIat 'nome=rva'     congela o alvo no exit/escrita (a IAT aponta para um `jmp $`)
#   -HookCall 'rvaCall=rvaFn' intercepta um call e grava o que o call RETORNA (rax e rdx)
#   -HookPos  'rva'           grava rax logo DEPOIS de um call, sem tocar no call
#   -HookStub 'rva=TEMPLATE'  stub proprio (hex) com {scratch}/{orig}; o unico primitivo que cobre
#                             os casos especiais (capturar seed, frame, rsp, registradores)
#   -HookSeed 'rva'           grava rcx/r8/rdx/r9 = regs[0..3] no ponto em que o alvo os escreve
#                             (o SEED do digest) e repete os 5 bytes originais
#   -SeguirRetorno            com -HookCall: trata (rax,rdx) do retorno como (ptr,len) e despeja
#
# ARMADILHAS MEDIDAS (todas custaram uma rodada; estao no relatorio da 8.5):
#   1. `call stub` que CHAMA a funcao original tem de reconstruir rsp == o rsp do call (S):
#      ao entrar no stub o rsp e S-8, entao `add rsp,8` ANTES do call e `sub rsp,8` depois. So
#      "manter alinhamento 16" NAO basta: se a funcao recebe 5o argumento NA PILHA (padrao
#      Windows x64), ela le de [rsp+0x28] e um rsp errado da ponteiro lixo -> 0xC0000005.
#      Medido: alvo com `mov [rsp+0x20], rax` antes do call = 5o argumento.
#   2. Nao existe store absoluto de 64 bits sem registrador: o endereco da scratch entra por
#      `movabs rdx/r11, imm64`. Em stub que grava e RETORNA valor, use r11 (r10/r11 sao os
#      unicos livres depois de um call que devolve em rax/rdx).
#   3. Stub montado "byte a byte na mao" erra encoding (disp32 de 4 bytes, nao 2) e o sintoma e
#      0xC0000005 sem pista. Monte por TEMPLATE HEX e VALIDE com `python scripts/disasm-range.py`
#      numa copia do alvo antes de rodar (cada instrucao conferida) — foi assim que os stubs desta
#      ferramenta entraram em producao.
#   4. -HookCall, -HookPos e -HookStub NAO podem dividir a mesma area de scratch: cada um escreve
#      no seu momento e o ultimo apaga o anterior (medido: seed lido como zero).
#   5. `-EntradaHex` serve para senha binaria — mas se o alvo VALIDA a entrada (trim, decode,
#      UTF-8), bytes binarios podem virar entrada VAZIA e o digest passa a ser constante. Antes de
#      concluir "senha errada", instrumente a funcao que prepara a entrada e LE o que ela devolveu
#      (-HookCall + -SeguirRetorno). Foi o que separou "modelo errado" de "transporte errado".
#
# Uso:
#   powershell -File scripts/park-patch-run.ps1 -Target <exe> -Entrada 'abc' #       -HookCall '0x4659=0x1000' -SeguirRetorno -Patch '0x46de=48b92e90ad62fdad8f2ac3'
param(
    [Parameter(Mandatory)][string]$Target,
    [string]$Entrada = '',                  # texto (vai com quebra de linha)
    [string]$EntradaHex = '',               # bytes crus em hex (senha binaria) + quebra de linha
    [string[]]$Patch = @(),                 # 'rva=hexbytes' (aceita '0x' e virgulas)
    [string[]]$FreezeIat = @(),             # 'nome=0xrva' -> congela no exit/escrita
    [string[]]$HookCall = @(),              # 'rva-do-call=rva-da-funcao' -> grava rax E rdx do retorno
    [string[]]$HookPos = @(),               # 'rva' (logo DEPOIS de um call) -> grava rax
    [string[]]$HookStub = @(),              # 'rva=HEX' (template com {scratch}/{orig}) -> stub proprio
    [string[]]$HookSeed = @(),              # 'rva' -> grava rcx/r8/rdx/r9 = regs[0..3] (o SEED)
    [switch]$SeguirRetorno,                 # -HookCall: trata (rax,rdx) como (ptr,len) e despeja
    [int]$EsperaPromptMs = 1500,
    [int]$EsperaSaidaMs = 3000,
    [string]$OutDir = '',
    [switch]$SalvarRegioes
)
$ErrorActionPreference = 'Stop'

# Pitfall do projeto (AGENTS.md): sob `powershell -File`, `-Patch a,b` chega como UMA string.
function Split-Lista([string[]]$itens) {
    $out = @()
    foreach ($i in $itens) { $out += ($i -split ',') }
    return @($out | Where-Object { $_ -match '=' })
}
$Patch = Split-Lista $Patch
$HookPos = @((($HookPos -join ',') -split ',') | Where-Object { "$_".Trim() -ne '' })
$HookStub = Split-Lista $HookStub
$HookSeed = @((($HookSeed -join ',') -split ',') | Where-Object { "$_".Trim() -ne '' })
$FreezeIat = Split-Lista $FreezeIat

Add-Type -Namespace PR -Name Mem -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
[DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr, IntPtr size, uint allocType, uint protect);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool VirtualProtectEx(IntPtr h, IntPtr addr, IntPtr size, uint newProtect, out uint oldProtect);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out IntPtr written);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out IntPtr read);
[DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION mbi, IntPtr len);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
    public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
}
'@
function Get-Err { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }

$pi = New-Object System.Diagnostics.ProcessStartInfo
$pi.FileName = (Resolve-Path $Target).Path
$pi.RedirectStandardInput = $true
$pi.RedirectStandardOutput = $true
$pi.RedirectStandardError = $true
$pi.UseShellExecute = $false
$pi.CreateNoWindow = $true
$p = [System.Diagnostics.Process]::Start($pi)
$sb = New-Object System.Text.StringBuilder
$sw = [System.Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt $EsperaPromptMs) {
    while ($p.StandardOutput.Peek() -ge 0) { [void]$sb.Append([char]$p.StandardOutput.Read()) }
    Start-Sleep -Milliseconds 100
}
Write-Host ("pid={0} parado: {1}" -f $p.Id, ($sb.ToString().Trim() -replace "`r?`n", ' / '))
if ($p.HasExited) { Write-Host "alvo ja saiu"; exit 1 }

$base = [int64]$p.Modules[0].BaseAddress
Write-Host ("base 0x{0:x}" -f $base)
$h = [PR.Mem]::OpenProcess(0x0C38, $false, $p.Id)   # QUERY|VM_READ|VM_WRITE|VM_OP|SUSPEND_RESUME
if ($h -eq [IntPtr]::Zero) { throw "OpenProcess falhou (err=$(Get-Err))" }
$wr = [IntPtr]::Zero

foreach ($par in $Patch) {
    $rvaTxt, $hex = $par.Split('=')
    $alvo = [IntPtr]($base + [Convert]::ToInt64(($rvaTxt -replace '^0x', ''), 16))
    $bytes = [byte[]]([regex]::Matches($hex, '..') | ForEach-Object { [Convert]::ToByte($_.Value, 16) })
    $lidos = [byte[]]::new($bytes.Length)
    $rd = [IntPtr]::Zero
    [void][PR.Mem]::ReadProcessMemory($h, $alvo, $lidos, $bytes.Length, [ref]$rd)
    $old = [uint32]0
    if (-not [PR.Mem]::VirtualProtectEx($h, $alvo, [IntPtr]$bytes.Length, 0x40, [ref]$old)) { throw "VirtualProtectEx falhou em $rvaTxt (err=$(Get-Err))" }
    if (-not [PR.Mem]::WriteProcessMemory($h, $alvo, $bytes, $bytes.Length, [ref]$wr)) { throw "WriteProcessMemory falhou em $rvaTxt (err=$(Get-Err))" }
    [void][PR.Mem]::VirtualProtectEx($h, $alvo, [IntPtr]$bytes.Length, $old, [ref]$old)
    Write-Host ("  patch RVA {0} em VA 0x{1:x}: {2} -> {3}" -f $rvaTxt, [int64]$alvo,
        (($lidos | ForEach-Object { '{0:x2}' -f $_ }) -join ''), $hex)
}

$scratch = [IntPtr]::Zero
if ($HookCall.Count -gt 0) {
    # Hook de call-site: troca `call <fn>` por `call <stub>`, e o stub chama a funcao original,
    # grava o retorno (rax) em SCRATCH e volta. Serve para VER o valor que o alvo calcula.
    $scratch = [PR.Mem]::VirtualAllocEx($h, [IntPtr]::Zero, [IntPtr]0x1000, 0x3000, 0x40)
    if ($scratch -eq [IntPtr]::Zero) { throw "VirtualAllocEx(scratch) falhou" }
    foreach ($par in $HookCall) {
        $rvaCall, $rvaFn = $par.Split('=')
        $fn = $base + [Convert]::ToInt64(($rvaFn -replace '^0x', ''), 16)
        $call = $base + [Convert]::ToInt64(($rvaCall -replace '^0x', ''), 16)
        # ARMADILHA MEDIDA: alocar com dica em [IntPtr]::Zero devolve endereco longe (>2 GB) e o
        # `call rel32` do patch nao alcanca. Aloca perto da imagem, tentando alguns passos.
        $stub = [IntPtr]::Zero
        foreach ($passo in 0x600000, 0x800000, 0x1000000, 0x1800000, 0x2000000) {
            $dica = [IntPtr]($base + $passo)
            $stub = [PR.Mem]::VirtualAllocEx($h, $dica, [IntPtr]0x1000, 0x3000, 0x40)
            if ($stub -ne [IntPtr]::Zero) { break }
        }
        if ($stub -eq [IntPtr]::Zero) { throw "VirtualAllocEx(stub) falhou perto da imagem" }
        $dist = [int64]$stub - ([int64]$call + 5)
        if ([Math]::Abs($dist) -gt 0x7FFFFFFF) { throw "stub longe demais para rel32 (0x$($dist.ToString('x')))" }
        # ARMADILHA MEDIDA (0xC0000005): o call original em 0x4690 passa um 5o ARGUMENTO NA
        # PILHA (0x4678: mov [rsp+0x20], rax). Ao entrar no stub por `call stub` o rsp esta S-8;
        # se o stub chamar a funcao sem devolver rsp para S, ela le os argumentos de pilha de
        # outro endereco -> ponteiro lixo -> access violation. Tem de ser `add rsp,8` ANTES do
        # call (e desfazer depois), que e o que reproduz "rsp == S" do call original.
        # ARMADILHA MEDIDA (0xC0000005): o call original passa um 5o ARGUMENTO NA PILHA. Para o
        # stub reproduzir o contrato do call, rsp dentro dele tem de voltar a ser o rsp do call
        # (S): `add rsp,8` compensa o push do proprio `call stub`, e no fim `sub rsp,8` volta a
        # condicao de entrada. rax E rdx sao gravados (o chamador usa os DOIS retornos).
        # ARMADILHA MEDIDA: nao ha store absoluto de 64 bits sem registrador -- o ponteiro da
        # scratch vai para r11 (r10/r11 sao os unicos livres depois do call).
        $hookScratch = [IntPtr]([int64]$scratch + 0x800)   # cada hook com area propria (armadilha 4)
        $tpl = '4883C40848B8{fn}49BB{scratch}FFD0498903498953084883EC08C3'
        $fnHex = ([BitConverter]::ToString([BitConverter]::GetBytes([int64]$fn)) -replace '-','')
        $sHex = ([BitConverter]::ToString([BitConverter]::GetBytes([int64]$hookScratch)) -replace '-','')
        $hexStub = $tpl.Replace('{fn}', $fnHex).Replace('{scratch}', $sHex)
        $sc = [byte[]]([regex]::Matches($hexStub, '..') | ForEach-Object { [Convert]::ToByte($_.Value, 16) })
        if (-not [PR.Mem]::WriteProcessMemory($h, $stub, $sc, $sc.Length, [ref]$wr)) { throw "write stub falhou" }
        $rel = [int64]$stub - ([int64]$call + 5)
        $patchCall = [byte[]]::new(5)
        $patchCall[0] = 0xE8
        [BitConverter]::GetBytes([int32]$rel).CopyTo($patchCall, 1)
        $old = [uint32]0
        if (-not [PR.Mem]::VirtualProtectEx($h, [IntPtr]$call, [IntPtr]5, 0x40, [ref]$old)) { throw "protect(call) falhou" }
        if (-not [PR.Mem]::WriteProcessMemory($h, [IntPtr]$call, $patchCall, 5, [ref]$wr)) { throw "patch(call) falhou" }
        [void][PR.Mem]::VirtualProtectEx($h, [IntPtr]$call, [IntPtr]5, $old, [ref]$old)
        Write-Host ("  hook: call RVA {0} -> stub 0x{1:x} (grava rax em scratch 0x{2:x})" -f $rvaCall, [int64]$stub, [int64]$scratch)
    }
}

if ($HookPos.Count -gt 0) {
    # GRAVADOR POS-CALL (o hook de call-site acima mede 0xC0000005: a funcao do digest reage a ser
    # chamada de dentro de um stub, com endereco de retorno diferente -- ver relatorio). Aqui o
    # `call` original fica INTACTO: troca-se os 5 bytes SEGUINTES por `call stub`, e o stub
    # (a) grava rax em scratch, (b) REPETE os 5 bytes originais, (c) `ret` para o call+5.
    # O digest roda com fluxo de pilha e return-address identicos ao original.
    # ARMADILHA 4: cada modo de hook tem a SUA area. O -HookPos grava rax em posScratch; se
    # dividisse a area com -HookCall/-HookStub (que escrevem depois), o valor seria apagado.
    $posScratch = [PR.Mem]::VirtualAllocEx($h, [IntPtr]::Zero, [IntPtr]0x1000, 0x3000, 0x40)
    if ($posScratch -eq [IntPtr]::Zero) { throw "VirtualAllocEx(posScratch) falhou" }
    foreach ($rvaTxt in $HookPos) {
        $pos  = [IntPtr]($base + [Convert]::ToInt64(($rvaTxt -replace '^0x',''), 16))
        $orig = [byte[]]::new(5)
        $rd = [IntPtr]::Zero
        if (-not [PR.Mem]::ReadProcessMemory($h, $pos, $orig, 5, [ref]$rd)) { throw "ReadProcessMemory(orig) falhou" }
        $stub = [IntPtr]::Zero
        foreach ($passo in 0x600000, 0x800000, 0x1000000, 0x1800000, 0x2000000) {
            $stub = [PR.Mem]::VirtualAllocEx($h, [IntPtr]($base + $passo), [IntPtr]0x1000, 0x3000, 0x40)
            if ($stub -ne [IntPtr]::Zero) { break }
        }
        if ($stub -eq [IntPtr]::Zero) { throw "VirtualAllocEx(stub) falhou" }
        $dist = [int64]$stub - ([int64]$pos + 5)
        if ([Math]::Abs($dist) -gt 0x7FFFFFFF) { throw "stub longe demais para rel32" }
        # GRAVADOR POS-CALL (generico): troca os 5 bytes SEGUINTES ao call por `call stub`; o stub
        # grava rax em scratch e REPETE os 5 bytes originais. O call original fica INTACTO, entao a
        # funcao chamada ve return-address e pilha originais (um hook de call-site foi medido como
        # 0xC0000005 neste alvo: a funcao do digest reage a ser chamada de dentro de outro frame).
        $tpl = '48BA{scratch}488902{orig}C3'
        $sHex = ([BitConverter]::ToString([BitConverter]::GetBytes([int64]$posScratch)) -replace '-','')
        $oHex = (($orig | ForEach-Object { '{0:x2}' -f $_ }) -join '')
        $sc = [byte[]]([regex]::Matches($tpl.Replace('{scratch}', $sHex).Replace('{orig}', $oHex), '..') | ForEach-Object { [Convert]::ToByte($_.Value, 16) })
        if (-not [PR.Mem]::WriteProcessMemory($h, $stub, $sc, $sc.Length, [ref]$wr)) { throw "write stub falhou" }
        $patchCall = [byte[]]::new(5)
        $patchCall[0] = 0xE8
        [BitConverter]::GetBytes([int32]$dist).CopyTo($patchCall, 1)
        $old = [uint32]0
        if (-not [PR.Mem]::VirtualProtectEx($h, $pos, [IntPtr]5, 0x40, [ref]$old)) { throw "protect(pos) falhou" }
        if (-not [PR.Mem]::WriteProcessMemory($h, $pos, $patchCall, 5, [ref]$wr)) { throw "patch(pos) falhou" }
        [void][PR.Mem]::VirtualProtectEx($h, $pos, [IntPtr]5, $old, [ref]$old)
        Write-Host ("  gravador pos-call: RVA {0} (bytes {1} repetidos no stub 0x{2:x}) -> rax em scratch 0x{3:x}" -f `
            $rvaTxt, (($orig | ForEach-Object { '{0:x2}' -f $_ }) -join ''), [int64]$stub, [int64]$posScratch)
    }
}

if ($HookStub.Count -gt 0) {
    # Stub PROPRIO: o template (hex) vem do usuario e pode conter {scratch} (endereco da area) e
    # {orig} (os 5 bytes substituidos, repetidos dentro do stub). E o primitivo que cobre o que os
    # outros nao cobrem: gravar rsp, gravar varios registradores, gravar memoria apontada.
    # Ex.: gravar rsp  -> '49BB{scratch}498923{orig}C3'
    #      gravar 4 regs -> '49BB{scratch}4989034D8943084989531049894B18{orig}C3'
    $stubScratch = [PR.Mem]::VirtualAllocEx($h, [IntPtr]::Zero, [IntPtr]0x1000, 0x3000, 0x40)
    if ($stubScratch -eq [IntPtr]::Zero) { throw "VirtualAllocEx(stubScratch) falhou" }
    foreach ($par1 in $HookStub) {
        $rvaTxt, $tplTxt = $par1.Split('=')
        $tpl = $tplTxt
        $pos = [IntPtr]($base + [Convert]::ToInt64(($rvaTxt -replace '^0x',''), 16))
        $orig = [byte[]]::new(5); $rd = [IntPtr]::Zero
        if (-not [PR.Mem]::ReadProcessMemory($h, $pos, $orig, 5, [ref]$rd)) { throw "ReadProcessMemory falhou" }
        $stub = [IntPtr]::Zero
        foreach ($passo in 0x600000, 0x800000, 0x1000000, 0x1800000, 0x2000000) {
            $stub = [PR.Mem]::VirtualAllocEx($h, [IntPtr]($base + $passo), [IntPtr]0x1000, 0x3000, 0x40)
            if ($stub -ne [IntPtr]::Zero) { break }
        }
        if ($stub -eq [IntPtr]::Zero) { throw "VirtualAllocEx(stub) falhou" }
        $dist = [int64]$stub - ([int64]$pos + 5)
        if ([Math]::Abs($dist) -gt 0x7FFFFFFF) { throw "stub longe demais" }
        $rvaTxt, $tplTxt = $par1.Split('=')
        $tpl = $tplTxt
        # ARMADILHA MEDIDA (fechada no smoke da 8.5): aqui a area e a $stubScratch. Com $scratch
        # (o que estava antes) o stub so tinha area se -HookCall tambem fosse usado; sozinho, ele
        # escrevia no ENDERECO 0 -> 0xC0000005 no alvo e leitura de zeros (parecia "hook nao pegou").
        $sHex = ([BitConverter]::ToString([BitConverter]::GetBytes([int64]$stubScratch)) -replace '-','')
        $oHex = (($orig | ForEach-Object { '{0:x2}' -f $_ }) -join '')
        $sc = [byte[]]([regex]::Matches($tpl.Replace('{scratch}',$sHex).Replace('{orig}',$oHex), '..') | ForEach-Object { [Convert]::ToByte($_.Value, 16) })
        if (-not [PR.Mem]::WriteProcessMemory($h, $stub, $sc, $sc.Length, [ref]$wr)) { throw "write stub falhou" }
        $patchCall = [byte[]]::new(5); $patchCall[0] = 0xE8
        [BitConverter]::GetBytes([int32]$dist).CopyTo($patchCall, 1)
        $old = [uint32]0
        if (-not [PR.Mem]::VirtualProtectEx($h, $pos, [IntPtr]5, 0x40, [ref]$old)) { throw "protect falhou" }
        if (-not [PR.Mem]::WriteProcessMemory($h, $pos, $patchCall, 5, [ref]$wr)) { throw "patch falhou" }
        [void][PR.Mem]::VirtualProtectEx($h, $pos, [IntPtr]5, $old, [ref]$old)
        Write-Host ("  gravador de frame: RVA {0} (bytes {1} repetidos) -> rsp em scratch 0x{2:x}" -f `
            $rvaTxt, (($orig | ForEach-Object { '{0:x2}' -f $_ }) -join ''), [int64]$stubScratch)
    }
}

if ($HookSeed.Count -gt 0) {
    # Captura o SEED: no ponto escolhido, rcx/r8/rdx/r9 sao os regs[0..3] prestes a serem gravados
    # (ex.: o `mov [r..]` que copia os quatro para a area do digest). O stub grava os quatro e
    # REPETE os 5 bytes originais (a gravacao original).
    # ARMADILHA MEDIDA (fechada no smoke da 8.5): este modo tinha area propria em $scratch mas
    # imprimia $stubScratch (nulo sem -HookStub) E nao estava declarado no param() -- ou seja, era
    # codigo morto e o modo que produziu o "SEED capturado" do relatorio da 8.5 nao existia na
    # ferramenta promovida. Agora tem area $seedScratch e entra na lista de areas lidas.
    $seedScratch = [PR.Mem]::VirtualAllocEx($h, [IntPtr]::Zero, [IntPtr]0x1000, 0x3000, 0x40)
    if ($seedScratch -eq [IntPtr]::Zero) { throw "VirtualAllocEx(seedScratch) falhou" }
    foreach ($rvaTxt in $HookSeed) {
        $pos = [IntPtr]($base + [Convert]::ToInt64(($rvaTxt -replace '^0x',''), 16))
        $orig = [byte[]]::new(5); $rd = [IntPtr]::Zero
        if (-not [PR.Mem]::ReadProcessMemory($h, $pos, $orig, 5, [ref]$rd)) { throw "ReadProcessMemory falhou" }
        $stub = [IntPtr]::Zero
        foreach ($passo in 0x600000, 0x800000, 0x1000000, 0x1800000, 0x2000000) {
            $stub = [PR.Mem]::VirtualAllocEx($h, [IntPtr]($base + $passo), [IntPtr]0x1000, 0x3000, 0x40)
            if ($stub -ne [IntPtr]::Zero) { break }
        }
        if ($stub -eq [IntPtr]::Zero) { throw "VirtualAllocEx(stub) falhou" }
        $dist = [int64]$stub - ([int64]$pos + 5)
        if ([Math]::Abs($dist) -gt 0x7FFFFFFF) { throw "stub longe demais" }
        $tpl = '49BB{scratch}4989034D8943084989531049894B18{orig}C3'
        $sHex = ([BitConverter]::ToString([BitConverter]::GetBytes([int64]$seedScratch)) -replace '-','')
        $oHex = (($orig | ForEach-Object { '{0:x2}' -f $_ }) -join '')
        $sc = [byte[]]([regex]::Matches($tpl.Replace('{scratch}',$sHex).Replace('{orig}',$oHex), '..') | ForEach-Object { [Convert]::ToByte($_.Value, 16) })
        if (-not [PR.Mem]::WriteProcessMemory($h, $stub, $sc, $sc.Length, [ref]$wr)) { throw "write stub falhou" }
        $patchCall = [byte[]]::new(5); $patchCall[0] = 0xE8
        [BitConverter]::GetBytes([int32]$dist).CopyTo($patchCall, 1)
        $old = [uint32]0
        if (-not [PR.Mem]::VirtualProtectEx($h, $pos, [IntPtr]5, 0x40, [ref]$old)) { throw "protect falhou" }
        if (-not [PR.Mem]::WriteProcessMemory($h, $pos, $patchCall, 5, [ref]$wr)) { throw "patch falhou" }
        [void][PR.Mem]::VirtualProtectEx($h, $pos, [IntPtr]5, $old, [ref]$old)
        Write-Host ("  gravador de seed: RVA {0} (bytes {1} repetidos) -> seed em scratch 0x{2:x}" -f `
            $rvaTxt, (($orig | ForEach-Object { '{0:x2}' -f $_ }) -join ''), [int64]$seedScratch)
    }
}

if ($FreezeIat.Count -gt 0) {
    $stub = [PR.Mem]::VirtualAllocEx($h, [IntPtr]::Zero, [IntPtr]0x1000, 0x3000, 0x40)
    if ($stub -eq [IntPtr]::Zero) { throw "VirtualAllocEx falhou (err=$(Get-Err))" }
    $wr = [IntPtr]::Zero
    [void][PR.Mem]::WriteProcessMemory($h, $stub, [byte[]](0xEB, 0xFE), 2, [ref]$wr)
    Write-Host ("  stub jmp $ em 0x{0:x}" -f [int64]$stub)
    $alvoAddr = [byte[]]::new(8)
    [BitConverter]::GetBytes([int64]$stub).CopyTo($alvoAddr, 0)
    foreach ($par in $FreezeIat) {
        $nome, $rvaTxt = $par.Split('=')
        $slot = [IntPtr]($base + [Convert]::ToInt64(($rvaTxt -replace '^0x',''), 16))
        $old = [uint32]0
        if (-not [PR.Mem]::VirtualProtectEx($h, $slot, [IntPtr]8, 0x04, [ref]$old)) { Write-Host "  $nome : protect falhou"; continue }
        if (-not [PR.Mem]::WriteProcessMemory($h, $slot, $alvoAddr, 8, [ref]$wr)) { Write-Host "  $nome : write falhou"; continue }
        [void][PR.Mem]::VirtualProtectEx($h, $slot, [IntPtr]8, $old, [ref]$old)
        Write-Host ("  IAT {0} em 0x{1:x} -> congelado" -f $nome, [int64]$slot)
    }
}

if ($EntradaHex -ne '') {
    $bytesSenha = [byte[]]([regex]::Matches($EntradaHex, '..') | ForEach-Object { [Convert]::ToByte($_.Value, 16) })
    $p.StandardInput.BaseStream.Write($bytesSenha, 0, $bytesSenha.Length)
    Write-Host ("entrada binaria enviada: {0} bytes" -f $bytesSenha.Length)
}
$p.StandardInput.Write($Entrada + "`n")
$p.StandardInput.Flush()
# ARMADILHA MEDIDA (round 8.5): ler com Peek()/Read() DEPOIS da entrada voltava vazio e o alvo
# aparecia como "saiu" — inclusive no baseline, ou seja, o defeito era do script, nao do alvo.
# Aqui a leitura e assincrona com espera limitada: nao bloqueia se o alvo ficar preso (congelado).
$tarefa = $p.StandardOutput.ReadToEndAsync()
[void]$tarefa.Wait($EsperaSaidaMs)
$saida = if ($tarefa.IsCompleted) { $tarefa.Result } else { '(tempo esgotado sem EOF; saida parcial abaixo)' }
Write-Host ("vivo={0} exitcode={1} leitura-completa={2}" -f (-not $p.HasExited),
    $(if ($p.HasExited) { $p.ExitCode } else { 'n/a' }), $tarefa.IsCompleted)
Write-Host "--- saida do alvo (depois da entrada) ---"
Write-Host $saida
Write-Host "--- fim ---"

if ($OutDir -ne '') {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $mbiSize = [Runtime.InteropServices.Marshal]::SizeOf([type]'PR.Mem+MEMORY_BASIC_INFORMATION')
    $addr = [IntPtr]::Zero
    $buf = New-Object byte[] (1MB)
    $reg = 0; $tot = [int64]0
    while ($true) {
        $mbi = New-Object 'PR.Mem+MEMORY_BASIC_INFORMATION'
        if ([PR.Mem]::VirtualQueryEx($h, $addr, [ref]$mbi, [IntPtr]$mbiSize) -eq [IntPtr]::Zero) { break }
        $size = [int64]$mbi.RegionSize
        $prot = $mbi.Protect
        if (($mbi.State -eq 0x1000) -and (($prot -band 0x100) -eq 0) -and (($prot -band 0xFF) -in 0x02, 0x04, 0x20, 0x40) -and $size -gt 0) {
            $reg++
            $fs = $null
            if ($SalvarRegioes) { $fs = [IO.File]::Open((Join-Path $OutDir ("r{0:d2}-0x{1:x}-{2}.bin" -f $reg, [int64]$mbi.BaseAddress, $size)), 'Create') }
            $off = [int64]0
            while ($off -lt $size) {
                $pedaco = [int][Math]::Min([int64]$buf.Length, $size - $off)
                $lidos = [IntPtr]::Zero
                if ([PR.Mem]::ReadProcessMemory($h, [IntPtr]([int64]$mbi.BaseAddress + $off), $buf, $pedaco, [ref]$lidos) -and $lidos.ToInt64() -gt 0) {
                    $n = [int]$lidos.ToInt64(); $tot += $n
                    if ($fs) { $fs.Write($buf, 0, $n) }
                }
                $off += $pedaco
            }
            if ($fs) { $fs.Close() }
        }
        $addr = [IntPtr]([int64]$mbi.BaseAddress + $size)
    }
    Write-Host ("regioes lidas={0} bytes={1:N0}" -f $reg, $tot)
}
# Cada modo de hook tem a SUA area de scratch (armadilha 4): ler TODAS as que existirem.
# ARMADILHA MEDIDA (fechada no smoke da 8.5): escolher so UMA area (stub > pos > call) escondia as
# outras — com -HookPos e -HookStub juntos, o valor do -HookPos simplesmente nao aparecia na saida.
# ARMADILHA MEDIDA: variavel de tipo IntPtr vinda de um modo que NAO rodou chega como $null, e
# [IntPtr]$null dentro do ReadProcessMemory estoura ("nao e possivel converter nulo"); por isso a
# lista e montada so com as areas alocadas e o cast e feito na hora de usar.
$areas = @()
if ($seedScratch) { $areas += [pscustomobject]@{ Nome = 'seed (-HookSeed)'; End = $seedScratch; Modo = 'seed' } }
if ($stubScratch) { $areas += [pscustomobject]@{ Nome = 'stub proprio (-HookStub)'; End = $stubScratch; Modo = 'stub' } }
if ($posScratch) { $areas += [pscustomobject]@{ Nome = 'pos-call (-HookPos)'; End = $posScratch; Modo = 'pos' } }
if ($scratch) { $areas += [pscustomobject]@{ Nome = 'call-site (-HookCall)'; End = $scratch; Modo = 'call' } }
foreach ($area in $areas) {
    $bufS = [byte[]]::new(64)
    $rdS = [IntPtr]::Zero
    if ([PR.Mem]::ReadProcessMemory($h, [IntPtr]$area.End, $bufS, 64, [ref]$rdS)) {
        Write-Host ("--- area lida: {0}" -f $area.Nome)
        Write-Host ("--- SCRATCH 0x{0:x}: retorno do hook = 0x{1} (little-endian)" -f [int64]$area.End,
            (($bufS[7..0] | ForEach-Object { '{0:x2}' -f $_ }) -join ''))
        if ($area.Modo -eq 'seed') {
            # Ordem gravada pelo stub: rcx, r8, rdx, r9 = regs[0..3] do seed.
            Write-Host ("    SEED capturado: 0x{0:x16}  0x{1:x16}  0x{2:x16}  0x{3:x16}" -f `
                [BitConverter]::ToUInt64($bufS, 0), [BitConverter]::ToUInt64($bufS, 8),
                [BitConverter]::ToUInt64($bufS, 16), [BitConverter]::ToUInt64($bufS, 24))
        }
        if ($area.Modo -eq 'call') {
            $bufH = [byte[]]::new(16); $rdH = [IntPtr]::Zero
            [void][PR.Mem]::ReadProcessMemory($h, $hookScratch, $bufH, 16, [ref]$rdH)
            $rax = [BitConverter]::ToUInt64($bufH, 0); $rdx = [BitConverter]::ToUInt64($bufH, 8)
            Write-Host ("    retorno do call: rax=0x{0:x} rdx=0x{1:x} ({1})" -f $rax, $rdx)
            if ($SeguirRetorno -and $rax -ne 0 -and $rdx -gt 0 -and $rdx -le 512) {
                $bi = [byte[]]::new([int]$rdx); $r4 = [IntPtr]::Zero
                if ([PR.Mem]::ReadProcessMemory($h, [IntPtr][int64]$rax, $bi, [int]$rdx, [ref]$r4)) {
                    Write-Host ("    (ptr,len) do retorno -> {0} bytes hex: {1}" -f $rdx, (($bi | ForEach-Object { '{0:x2}' -f $_ }) -join ''))
                    Write-Host ("    como texto: {0}" -f (($bi | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } }) -join ''))
                    if ($OutDir) { [IO.File]::WriteAllBytes((Join-Path $OutDir 'retorno-ptr-len.bin'), $bi) }
                } else { Write-Host "    (ptr,len) ilegivel" }
            }
        }
        if ($area.Modo -eq 'stub') {
            # O stub do usuario decide o que gravar; o caso tipico e um PONTEIRO (ex.: rsp ou o
            # endereco de uma estrutura). Aqui o valor em scratch[0] e seguido e 160 bytes dele
            # sao despejados -- util para ler um frame (regs, locais) de dentro da funcao.
            $ptr = [BitConverter]::ToInt64($bufS, 0)
            Write-Host ("    scratch[0] = 0x{0:x} (stub proprio)" -f $ptr)
            $bf = [byte[]]::new(160); $rf = [IntPtr]::Zero
            if ($ptr -gt 0x10000 -and [PR.Mem]::ReadProcessMemory($h, [IntPtr]$ptr, $bf, 160, [ref]$rf)) {
                $q = (0..15 | ForEach-Object { "0x{0:x16}" -f ([BitConverter]::ToUInt64($bf, $_ * 8)) }) -join '  '
                Write-Host ("    +0x00..+0x80 (16 qwords): {0}" -f $q)
                if ($OutDir) { [IO.File]::WriteAllBytes((Join-Path $OutDir 'hook-stub-dump.bin'), $bf) }
            } else { Write-Host "    (nao segui o ponteiro: valor fora de faixa ou memoria ilegivel)" }
        }
        Write-Host ("    hex bruto: {0}" -f ((0..7 | ForEach-Object { '{0:x2}' -f $bufS[$_] }) -join ' '))
    } else { Write-Host ("scratch de {0} ilegivel em 0x{1:x} (processo saiu antes da leitura?)" -f $area.Nome, [int64]$area.End) }
}
[PR.Mem]::CloseHandle($h) | Out-Null
if (-not $p.HasExited) { $p.Kill() }

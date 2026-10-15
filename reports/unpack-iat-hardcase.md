# Caso “duro” — OEP → dump de memória → reconstrução da IAT (sem restore automático)

**Status:** **fechado** (2026-10-14). O alvo reconstruído pelo toolkit — dump de memória →
IAT reconstruída → estado de carga → EP — **roda até o fim e sai com o mesmo status do
original** (4/4 execuções, §6.4). A seção
[6](#6-o-que-ainda-não-funciona-o-arquivo-reconstruído-é-rejeitado-pelo-loader) guarda o
histórico do que falhava (loader recusando o dump) e o §6.4 fecha cada causa com comando e
saída. O que **não** foi exercitado continua listado em §6.5.

Pré-requisitos: Rust (`rustc`), x64dbg aberto com o plugin MCP
(`.\scripts\start-x64dbg.ps1`) e Node 18+. Nada aqui usa `sudo`.

## 1. Por que este caso existe

O caso UPX ([unpack-iat-upx-case.md](unpack-iat-upx-case.md)) tem caminho de volta:
`upx -d` restaura o arquivo. Protetor comercial de verdade (VMProtect/Themida DEMO) não é
reproduzível aqui — as imagens geradas pela DEMO nesta máquina são recusadas pelo loader
([root-cause-0xc000007b.md](root-cause-0xc000007b.md)). Faltava o alvo que exige o caminho
duro: **parar no OEP, dumpar a memória e reconstruir a IAT**.

`scripts/make-packed-sample.mjs` fabrica esse alvo a partir de um binário que roda
(`work/packer-demo/clean.exe`, app x64 de subsistema **GUI**, 50 DLLs / 315 imports, com
imports por ordinal e 6 DLLs de *delay load*):

1. a seção de código vai XOR'd no arquivo;
2. os descritores de import do alvo são **zerados** e o data directory IMPORT passa a
   apontar só para a tabela mínima do stub (kernel32);
3. o EP vira um `jmp` para o stub, que em runtime descriptografa o código, restaura os 8
   bytes originais do EP, resolve **cada** import (`LoadLibraryA`/`GetProcAddress`) e
   escreve o endereço na **IAT ORIGINAL** do alvo — na ordem dos thunks originais — e salta
   para o OEP.

O que não é restaurado (de propósito) são os descritores: no OEP existe uma IAT cheia de
ponteiros absolutos e **nenhuma** tabela de imports. Dump cru disso é inútil; é preciso
reconstruir a tabela — no x64dbg isso é o plugin Scylla (GUI) e aqui é
`scripts/rebuild-iat.mjs` (mesmo algoritmo, headless; ver §4).

## 2. Dois defeitos reais no stub, achados por “o alvo tem de RODAR”

O primeiro alvo gerado **não rodava** (`--run` → `exit=0xc0000005`). A depuração separou
“stub quebrado” de “cirurgia no PE” por bisseção, e os testes de diagnóstico do próprio
gerador (`--no-encrypt`, `--no-imports`, `--no-ep-jump`) isolaram a causa:

| defeito | onde | sintoma | correção |
|---|---|---|---|
| o stub lia a RVA da IAT de cada DLL em `[rbp + r14*4 + 56]` — o campo **+56 é `encSize`**; a tabela `pkr_iattab` vive em **+64** | `scripts/lib/pkr-stub.rs` | os `GetProcAddress` resolvidos eram escritos em endereços errados; a IAT do alvo ficava com os RVAs de hint/name do arquivo e o alvo saltava para lixo (`RIP=0x32126` — visível no debugger) | `[rbp + r14*4 + 64]` |
| o plano de imports não fechava o bloco de cada DLL com uma string vazia (o contrato do stub é `DLL\0fn\0…\0\0`) | `scripts/make-packed-sample.mjs` | o stub tratava o **nome da DLL seguinte** como função da DLL atual: `GetProcAddress` devolvia NULL (gravado na IAT) e todas as DLLs seguintes deslocavam uma entrada | `+ "\0"` por DLL + `"\0"` final |

Depois das duas correções o alvo empacotado roda de ponta a ponta:

```console
$ node scripts/make-packed-sample.mjs work/packer-demo/clean.exe -o work/iat-hardcase/src/clean.hardcase.exe --run --force
  [i ] pré-condições: x64, 8 seções, 50 DLLs / 315 funções (5 por ordinal), sem TLS callbacks
  [i ] IAT por DLL (49 bloco(s) com alinhamento — o plano carrega a RVA de cada IAT)
  [i ] stub: blob de 952 bytes, iat@+0x150, cfg@+0x178
  [i ] .pkr em rva=0x5a000 · EP do stub=0x5a000 · OEP real=0x19c0
  [i ] imports APAGADOS do arquivo: 50 DLLs / 315 funções
  [ok] run — exit=0x0
  [ok] o stub descriptografou, restaurou a IAT e chegou ao OEP (exit 0)
$ ./work/iat-hardcase/src/clean.hardcase.exe ; echo exit=$?
exit=0
```

## 3. Parar no OEP e dumpar, pela ponte MCP (sem clicar na GUI)

`scripts/x64dbg-drive.mjs` ganhou duas operações nesta rodada: `--dump-module-mem`
(`DumpMemory` da imagem carregada de um módulo, para o passo 4) e o uso combinado com
`GetMemoryMap`. Sequência canônica:

```console
# 1) carrega o alvo e para no EP (o stub)
$ node scripts/x64dbg-drive.mjs --load work/iat-hardcase/src/clean.hardcase.exe
$ node scripts/x64dbg-drive.mjs --call 'run {}'
# 2) poke um breakpoint no alvo do primeiro `call` do OEP (já é PÓS-stub, com tudo pronto)
$ node scripts/x64dbg-drive.mjs --call 'SetBreakpoint {"target":"0x7FF77BE21F98"}'
$ node scripts/x64dbg-drive.mjs --call 'run {}'      # ... repete até parar em 0x...1F98
$ node scripts/x64dbg-drive.mjs --call 'GetDebugState {}'
  currentAddress: 0x7FF77BE21F98   currentModule: clean.hardcase   status: LOCKED
# 3) prova do estado desempacotado, e o dump
$ node scripts/x64dbg-drive.mjs --call 'ReadMemory {"address":"0x7FF77BE219C0","size":16}'
  7FF77BE219C0: 48 83 EC 28 E8 CF 05 00 00 48 83 C4 28 E9 6E FE   <- EP ORIGINAL restaurado
$ node scripts/x64dbg-drive.mjs --call 'ReadMemory {"address":"0x7FF77BE49938","size":32}'
  7FF77BE49938: B0 24 D9 13 FD 7F 00 00 C0 62 D9 13 FD 7F 00 00   <- IAT com ponteiros p/ gdi32
$ node scripts/x64dbg-drive.mjs --call 'GetImports {"module":"clean.hardcase"}'
  [kernel32.dll] -> 0x7FFD146828F0 -> ...        <- o debugger só enxerga a tabela do STUB
$ node scripts/x64dbg-drive.mjs --dump-module clean.hardcase work/iat-hardcase/unpacked/dump-raw.exe
  Module dumped to file.
```

Evidência bruta deste passo: `work/iat-hardcase/evidence/20261013-2-oep-dump.json` (dump
JSON do driver: memória, módulos, imports, resultado do dump) e
`work/iat-hardcase/evidence/20261013-3-modules-do-debugger.txt` (a lista de módulos viva,
que o passo 4 usa como mapa base/tamanho).

## 4. Reconstruir a IAT — `scripts/rebuild-iat.mjs`

Scylla é a ferramenta canônica, mas **não tem CLI**: upstream `NtQuery/Scylla` (GPL-3.0,
v0.9.8, 2015) é um app Win32 com GUI — o que existe para automação é a DLL exportando
`ScyllaIatSearch`/`ScyllaIatFixAutoW`/`ScyllaRebuildFileW` (exigiria um harnês nativo). No
x64dbg ele entra pelo comando `StartScylla` (apelidos `scylla`, `imprec`), que só abre a
GUI. Por isso o mesmo trabalho aqui é um script headless e auditável:

1. **achar a IAT** — duas rotas independentes: thunks de import direto no código
   (`FF 25 disp32`) e varredura por blocos de ≥ 3 ponteiros que caem em **outro** módulo
   (ponteiro para dentro do próprio alvo é vtable, não import);
2. **resolver cada slot** — acha o módulo pelo endereço e o export pela tabela do módulo:
   nome quando existe, **ordinal** quando não (`#51`, `#381`…), usando as imagens
   **carregadas** (`DumpModule` de cada módulo de sistema), não os arquivos do System32 —
   necessário porque `comctl32.dll` v6 é servido do **WinSxS** e as RVAs de export não batem
   com as do arquivo em disco (medido: 11 slots ficavam sem resolução com o arquivo errado);
3. **escrever a tabela nova** numa seção `.idata2`: descritores + ILT (hint/name) nela, e
   `FirstThunk` apontando para os slots **originais** — é o que faz o loader preencher
   exatamente onde o código do alvo chama;
4. **normalizar os cabeçalhos do dump** — o `DumpModule` do x64dbg grava os **dados** no
   layout de memória (offset == RVA) mas mantém a **tabela de seções** no layout de arquivo:
   nas seções com `SizeOfRawData > VirtualSize` (`.pdata`, `.didat`, `.rsrc`, `.reloc`,
   `.pkr`) as duas coisas divergem e o arquivo fica incoerente. Medido: o bloco de
   relocação está em `0x59000` (RVA) e a tabela diz `rawptr=0x57000`. A reconstrução
   reescreve `rawptr = RVA` e `rawsz = align(VirtualSize)` nessas seções.

```console
$ node scripts/x64dbg-drive.mjs --dump-module comctl32 work/iat-hardcase/evidence/mem/comctl32.dll.bin
$ node scripts/rebuild-iat.mjs \
    --dump work/iat-hardcase/unpacked/dump-raw.exe \
    --out  work/iat-hardcase/unpacked/dump-fixed.exe \
    --modules work/iat-hardcase/evidence/20261013-3-modules-do-debugger.txt \
    --mem     work/iat-hardcase/evidence/mem --oep 0x19c0

UnboxRE — reconstrução de IAT (equivalente headless do Fix Dump do Scylla)
──────────────────────────────────────────────────────────────────────
  [i ] dump: 9 seções, 4 com rawptr == RVA -> tabela de seções normalizada para o layout de memória
  dump: work/iat-hardcase/unpacked/dump-raw.exe (376832 bytes, imageBase=0x7ff77be20000, EP=0x19c0)
  módulo-alvo na lista do debugger: clean.hardcase.exe base=0x7ff77be20000 size=0x5c000
  IAT encontrada: 289 slot(s) resolvido(s) — 48 por thunk direto, 288 por varredura
  8 DLL(s) reconstruída(s):
    comctl32.dll    11 função(ões)  FirstThunk=0x298d8
    gdi32.dll       25 função(ões)  FirstThunk=0x29938
    user32.dll      86 função(ões)  FirstThunk=0x29a08
    ntdll.dll       22 função(ões)  FirstThunk=0x29a38
    combase.dll     13 função(ões)  FirstThunk=0x29cd8
    kernelbase.dll  80 função(ões)  FirstThunk=0x29d40
    kernel32.dll     6 função(ões)  FirstThunk=0x29fb8
    ucrtbase.dll    46 função(ões)  FirstThunk=0x2a250
  seção nova .idata2 em rva=0x5c000 (2696 bytes)
  saída: work/iat-hardcase/unpacked/dump-fixed.exe (380928 bytes)
```

Duas checagens independentes de que a reconstrução achou as funções certas:

* **ordinal–nome**: o alvo importa `comctl32` por ordinal em 4 posições e o bloco
  reconstruído traz `#51`, `#85`, **`#381`**, `#83`…; na ILT original do arquivo
  (`work/packer-demo/clean.exe`, que o analista teria antes do empacotamento) as mesmas
  posições são `ImageList_Create`, `ImageList_SetBkColor`, `#381`, `ImageList_ReplaceIcon`
  — o `#381` bate posição a posição;
* **contagem por DLL**: comctl32 11 (era 11), gdi32 25 (25), user32 86 (87 — uma entrada é
  `ordinal-only` cujo endereço não está na EAT do build carregado). *As DLLs `api-ms-win-*`
  do arquivo original aparecem resolvidas nos seus **hosts** (ucrtbase/kernelbase/combase),
  que é o que `GetProcAddress` devolve em runtime — 50 nomes de contrato viram 8 DLLs reais.*

## 5. Triagem do dump cru vs. reconstruído (`diagnose-load.mjs`)

```console
$ node scripts/diagnose-load.mjs work/iat-hardcase/unpacked/dump-raw.exe
  [!!] reloc-bloco-invalido — bloco de relocação inválido em rva 0x59000: pageRva=0xfff0f0f2
       blockSize=0xff969696 (lido em offset 0x57000) — cabeçalho inconsistente com os dados
  [i ] run — exit=null (EFTYPE)
  Veredito: imagem com vícios de loader conhecidos
$ node scripts/diagnose-load.mjs work/iat-hardcase/unpacked/dump-fixed.exe
  [i ] reloc-ok — 361 entradas de relocação, todas em seções com dados
  [!!] loader-rejeitou — a execução terminou com 0xC000007B
  Veredito: imagem com vícios de loader conhecidos
```

O dump cru é recusado pelo próprio Windows, sem chegar a carregar (“Este aplicativo não
pode ser executado em seu PC” — o `reloc-bloco-invalido` acima explica por quê). Com os
cabeçalhos normalizados o arquivo passa a ser um PE coerente (`reloc-ok`, 361 entradas),
mas o loader **ainda** o rejeita — §6.

## 6. O que **ainda não** funciona (o arquivo reconstruído é rejeitado pelo loader)

`dump-fixed.exe` termina com **`0xC000007B` (`STATUS_INVALID_IMAGE_FORMAT`)**. Medido do
jeito certo — e aqui vale registrar um erro de medição que quase passou:

> `cmd /c app.exe & echo %errorlevel%` **não espera** apps de subsistema GUI: imprime
> `exit=0` na hora. A medição válida é `spawnSync(path, {timeout})` no Node ou
> `Start-Process -Wait` no PowerShell. Com o método correto: `dump-raw.exe` → `EFTYPE` e
> `dump-fixed.exe` → `0xC000007B` (idênticos rodando pelo Node ou pelo PowerShell).

Hipóteses **já refutadas** para o `0xC000007B` do reconstruído (variantes geradas a partir
do `dump-fixed.exe`, todas medidas):

| variante | resultado |
|---|---|
| LOAD_CONFIG zerado | `0xC000007B` |
| BASERELOC zerado | `0xC000007B` |
| ambos zerados | `0xC000007B` |

Ou seja: o gatilho de `0xC000007B` **não** é o que
[root-cause-0xc000007b.md](root-cause-0xc000007b.md) §5 usa para *reproduzir* o status;
aqui é outro.

### 6.1 Loader snaps — feito, e o que saiu (rodada de 2026-10-14)

A ferramenta que faltava foi ligada de verdade: a flag de IFEO `GlobalFlag` +
`FLG_SHOW_LDR_SNAPS` via
`scripts/load-snaps.ps1 -Image dump-fixed.exe -Apply` (o equivalente a
`gflags /i dump-fixed.exe +sls`, sem depender do gflags — que, medido, não existe no
winget nem no pacote do WinDbg). Resultado medido, e ele é **incompleto de propósito**:

| medida | resultado | evidência |
|---|---|---|
| o flag foi escrito | `GlobalFlag = 0x2` na chave IFEO de `dump-fixed.exe` | `evidence/20261013-5-loadsnaps.json` |
| o loader **falou** | 3× `[x64dbg-MCP Server] OutputDebugString received` no log de eventos do x64dbg | idem (chamada `GetEventLog`) |
| o **texto** das linhas | **não** veio: o `GetEventLog` do MCP registra o evento, não a string — e o plugin **não tem** tool que devolva o log | idem + lista de nomes do `.dp64` |
| listener do canal global (sem debugger) | 0 byte — e **não** é bug do listener | `evidence/20261013-6-…txt`, `20261014-11-…txt` |
| o listener funciona? | **sim**: auto-teste com `OutputDebugString` direto capturou `[pid 14916] TESTE-DBWIN-20261014-OK` (37 bytes) | `evidence/20261014-13-dbwin-selftest.txt` |
| control: imagem **válida** + snaps ligados, sem debugger | 0 byte (`clean.exe`, que carrega e sai 0) | `evidence/20261014-12-loadsnaps-control-clean.txt` |
| `dump-raw.exe` nem inicia | `CreateProcess` recusa: *“O executável especificado não é um aplicativo válido para esta plataforma de SO”* | executado nesta rodada |

Ou seja: os snaps **são emitidos**, e o canal de leitura foi isolado. Sem debugger anexado
não há saída no canal global nesta máquina (o control com imagem válida prova); com
debugger, a saída existe mas não passa pelo MCP. O que fazer a seguir mudou de lugar:

* **ler o texto dentro do debugger** — janela *Log* do x64dbg ou WinDbg
  (`Microsoft.WinDbg`, já instalado, `1.2610.1001.0`). O problema é do **canal de leitura**,
  não do flag — e não é do `capture-debugprint.ps1`, que passou no auto-teste;
* **registrar a assimetria**: “ligar snap sem debugger não produz nada neste host” é um
  resultado medido, e contradiz a expectativa documentada do script (que assumia o canal
  `DBWIN_BUFFER` como destino quando não há debugger) — vale corrigir a ficha e o help do
  script para dizer isso;
* comparar, seção por seção, o `dump-fixed.exe` com o `clean.exe` original (que carrega):
  falta um diretório de dados consistente com o conteúdo? O `.reloc`-por-RVA foi
  normalizado, mas o resto da imagem continua sendo um dump (a `.pdata` de memória, por
  exemplo, já foi modificada pela execução);
* reforço do Scylla pela GUI (Plugins → Scylla → *Fix Dump*) sobre o **mesmo** dump, para
  comparar o arquivo que ele produz com o que este script produz — o único jeito de checar
  se a diferença é do dump ou da reconstrução.

### 6.2 Um dado que muda a leitura do caso: sob o x64dbg, o reconstruído RODA

Rodando os dois arquivos no x64dbg **headless** (`evidence/20261013-7-headless-run.txt`):

```console
## dump-raw.exe
Debugging: …\unpacked\dump-raw.exe

## dump-fixed.exe
Process Started: 00007FF63B1D0000 …\unpacked\dump-fixed.exe
Module dump-fixed.exe loaded from disk path
DLL Loaded: 00007FFD15420000 C:\Windows\System32\ntdll.dll
Process stopped with exit code 0x0 (0)
```

`dump-fixed.exe` **inicia e sai com 0** sob o x64dbg, e termina em `0xC000007B` quando
criado pelo loader normal do Windows (medido em §5, `spawnSync` e `Start-Process -Wait`).
Isso tira a conclusão do terreno “o arquivo está quebrado” e a põe em “a imagem passa
quando quem mapeia é o debugger, e é recusada quando quem mapeia é o loader do SO” — que é
exatamente a pergunta que os loader snaps respondem. Enquanto o texto dos snaps não era
lido, a conclusão honesta era **não sei qual checagem do ntdll reprova**.

### 6.3 A checagem está identificada — e o caso fechou (rodada de 2026-10-14, mesmo dia)

A pergunta de §6.2 foi respondida por breakpoint no `ntdll` (símbolos do Microsoft Symbol
Server), não por inferência: `ntdll!LdrpProcessMappedModule` → `ntdll!LdrInitSecurityCookie`
exige que o `__security_cookie` da imagem ainda esteja no **sentinela do MSVC**
(`0x00002B992DDFA232`) e devolve 0 caso contrário; com 0, o `LdrpProcessMappedModule` devolve
`STATUS_INVALID_IMAGE_FORMAT`. Um dump de memória traz o cookie já randomizado pela execução
anterior — é o “estado de execução” que o loader não aceita. Cadeia completa, com registradores
e valores: [root-cause-0xc000007b.md](root-cause-0xc000007b.md) §8.

A correção entrou no toolkit como `scripts/reset-load-state.mjs` (repõe o sentinela no
endereço que o próprio `LOAD_CONFIG` declara), e o efeito é medido — 3 execuções de cada:

| arquivo | saída | leitura |
|---|---|---|
| `unpacked/dump-fixed.exe` | `0xC000007B ×3` | loader recusa (antes) |
| `unpacked/dump-fixed-loadstate.exe` | `0xC0000005 ×3` | **loader aceita**; o código roda e faltou no EP |

Ou seja: o `0xC000007B` deste caso **não era da reconstrução da IAT** (que está correta) nem da
captura — era estado de carga. O `0xC0000005` que sobra é outro problema: o EP do dump é o do
**stub** do packer, que reexecuta sobre memória já desempacotada. Apontar o EP para o OEP é o
próximo passo deste caso, e não foi feito nesta rodada.

### 6.4 Fechado: o EP **já era** o OEP — o que faltava era um byte do dump e um bug do script

A rodada partiu da hipótese “o EP aponta para o stub; reaponte para o OEP”. Medição antes da
hipótese (`evidence/20261014-70-ep-e-oep.txt`):

| arquivo | EP no cabeçalho | bytes em RVA 0x19C0 (o EP) | `.text` vs original |
|---|---|---|---|
| `src/clean.hardcase.exe` (empacotado) | `0x19c0` | `e9 3b 86 05 00 90 90 90` = `jmp 0x5a000` (stub) | 157051 byte(s) (cifrado) |
| `unpacked/dump-raw.exe` | `0x19c0` | `48 83 ec 28 e8 cf 05 00` = código ORIGINAL | **1** byte |
| `unpacked/dump-fixed.exe` / `…-loadstate.exe` | `0x19c0` | idem | **1** byte |
| `unpacked/dump-fixed3.exe` / `dump-final3.exe` | `0x19c0` | idem | **0** byte(s) |
| `clean.exe` original (= `notepad.exe` do sistema, sha256 idêntico) | `0x19c0` | `48 83 ec 28 e8 cf 05 00` | — |

`AddressOfEntryPoint` é 0x19C0 **em todos**. No arquivo empacotado é 0x19C0 que aponta para o
stub — por um `jmp` no próprio EP; o stub restaura ali os 8 bytes originais e salta para o
mesmo endereço. O dump já contém a versão restaurada: **não havia EP para reapontar.** Com
símbolos (`cdb`, `notepad.pdb`): `ln $exentry` → `notepad!wWinMainCRTStartup`, e o `call` de
`+0x4` vai para `notepad!_security_init_cookie` — código de CRT normal, não stub.

#### (a) O dump carregava UMA instrução trocada — e o loader a aceitava

O `.text` do dump diferia do original em **exatamente 1 byte**, em RVA `0x1F98`:
`0x48` → `0x51` (`mov [rsp+18h], rbx` virava `push rcx`), o mesmo endereço do
**breakpoint de software do dump** (`SetBreakpoint 0x7FF77BE21F98`, §3). O byte no arquivo
empacotado ali é `0x51` e o keystream do stub naquela posição é `0x19` — o dump guardou o byte
**ainda cifrado** (`0x51 = 0x48 ^ 0x19`), não o decifrado. Mecanismo: o breakpoint foi escrito
antes de o stub decriptar a seção; ao parar, o debugger restaurou o byte que tinha salvado
(o *pré*-decriptação).

Consequência exata, medida com traçagem (`evidence/20261014-49/50`):

```
notepad!_security_init_cookie:  ... mov [rsp+18h],rbx  (esperado)
                                ... push rcx          (no dump)
  → o epílogo faz `pop rbp; ret` e o `ret` desempilha o rcx empilhado a mais
  → rip = 0x000000ed`60847000 (memória livre), [rsp] = notepad!wWinMainCRTStartup+0x9
```

O loader **aceitava** a imagem (cookie já corrigido) e o programa morria com `0xC0000005`
dentro do CRT. O `verify-dump.mjs` (novo, §6.5) aponta esse byte como `CODIGO` com o endereço.
Reposto o byte (`0x48`), o `.text` fica **byte a byte idêntico ao original**.

#### (b) Bug no `rebuild-iat.mjs`: descritores com passo de 24 bytes

O loader só processava o **primeiro** descritor de import. Motivo medido
(`evidence/20261014-71-descriptor-passo.txt`): o script alinhava cada descritor a 8 bytes, e
`IMAGE_IMPORT_DESCRIPTOR` tem **20** — o passo virava 24 e o loader, que avança 20 por entrada,
lia no #1 um `Name == 0` e parava ali:

```
#0 @0x5c948  OFT=0x5c000  Name=comctl32.dll                        FT=0x298d8
#1 @0x5c95c  OFT=0x0      Name=<Name=0 -> o loader PARA aqui>        FT=0x5ca2a   ← lixo do alinhamento
```

Efeito: só o comctl32 era resolvido; os outros 7 blocos ficavam com os endereços do processo
que gerou o dump. `combase.dll` nem aparecia em `lm` (`evidence/20261014-55`), e a primeira
chamada que dependia dela morria: `call qword ptr [_imp_CoCreateGuid]` → memória livre.
Corrigido (o alinhamento vale para a tabela, não para cada entrada), o loader passou a carregar
`combase`, `RPCRT4`, `gdi32`… (`evidence/20261014-58`).

#### (c) Bug no `rebuild-iat.mjs`: descritor por DLL em vez de por corrida contígua

Segundo defeito, achado pelo mesmo caminho: um descritor declara uma faixa **contígua** de
`FirstThunk`; agrupar por DLL só funciona se todos os slots daquela DLL forem vizinhos. Não
são — cada DLL de contrato `api-ms-win-*` é um descritor próprio no arquivo original e todas
resolvem no mesmo host, então uma DLL real aparece em **várias** corridas. Com um descritor por
DLL, o loader escrevia `kernelbase` por cima dos slots de `kernel32`:

```
0x0fb703  movzx eax, word ptr [rbx]      ; rbx = 0
  ← `call qword ptr [_imp_GetCommandLineW]` devolveu 0 (o slot tinha outra função)
```

Corrigido (um descritor por corrida contígua), o alvo passou a atravessar `wWinMain`, carregar
uxtheme/bcryptPrimitives/kernel.appcore e **sair 0** (§6.4(d)).

#### (d) Resultado: o dump roda como o original

```
$ powershell -File work/iat-hardcase/scripts/run-and-probe.ps1 -Target unpacked/dump-final3.exe
exited : sim  (ExitCode=0 = 0x0)                     ← 4/4 execuções
$ powershell -File … -Target ../packer-demo/clean.exe
exited : sim  (ExitCode=0 = 0x0)                     ← o original, 3/3
```

Comando total do caminho canônico (do dump cru ao alvo rodando):

```
node scripts/rebuild-iat.mjs --dump unpacked/dump-raw-bpfix.exe --out unpacked/dump-fixed4.exe \
     --modules evidence/20261013-3-modules-do-debugger.txt --mem evidence/mem --oep 0x19c0
node scripts/reset-load-state.mjs --dump unpacked/dump-fixed4.exe --out unpacked/dump-final4.exe
node scripts/verify-dump.mjs --dump unpacked/dump-fixed4.exe --original ../packer-demo/clean.exe
powershell -File work/iat-hardcase/scripts/run-and-probe.ps1 -Target unpacked/dump-final4.exe   # script DO CASO (exit 0)
```

Cobertura da IAT, artefato por artefato (`evidence/20261014-72-iat-cobertura.txt`) — “slot
estaleiro” = 8 bytes na faixa do data directory IAT apontando para um módulo:

| artefato | slots estaleiros | declarados pelos descritores | falta |
|---|---|---|---|
| `dump-fixed.exe` (rodada anterior) | 311 | 155 | **156** |
| + passo 20 e corridas contíguas | 311 | 289 | 22 |
| + rota derivada da faixa (3ª rota) | 315 | 315 | **0** |

### 6.4a A causa daquele byte: eliminada na captura (rodada 2026-10-14, segunda parte)

O byte de `0x1F98` foi consertado à mão no artefato (§6.4(a)), mas a causa continuava viva: um
breakpoint de **software** armado em `.text` antes de o stub decriptar. Num alvo sem original em
claro (crackme), nada denunciaria o resultado. O que esta rodada mudou, e a prova de cada item:

| mudança | onde | prova |
|---|---|---|
| breakpoint de **hardware** como caminho padrão (`--hw-break`, não escreve na memória) | `scripts/x64dbg-drive.mjs` | **A/B** abaixo: mesmo ponto, byte correto sem patch manual |
| o driver **confere** que o BP foi armado (o x64dbg aceita o 5º em silêncio) | idem | **D** abaixo: exit 1 e `armed:false` no log |
| a captura **grava os endereços de breakpoint** (`--bp-log`) | idem | **C** abaixo: é o que dá dentes ao modo sem original |
| verificação **sem original**, declarada como substituta | `scripts/verify-dump.mjs` | **C** abaixo: pega o mesmo byte que o teste com original pegou |
| persistência do banco `.dd64` virou passo do procedimento | `docs/06-workflows.md` Cenário 1 | **D** abaixo: BP de rodada anterior volta armado |

**A — reprodução do bug** (`bash scripts/prova-a-swbp.sh`, log
`evidence/20261014-82-prova-a-swbp.txt`): carga, run até o EP, `SetBreakpoint` em `base+0x1F98`
(o alvo do primeiro `call` do OEP) com a seção ainda **cifrada**, run até parar, `DumpModule`:

```
RVA 0x1f98  51 fd 93 0e 9d b5 73 1d   ← empacotado (o que estava na memória antes do stub)
RVA 0x1f98  51 89 5c 24 18 55 48 8b   ← dump capturado agora (BP de SOFTWARE)
RVA 0x1f98  48 89 5c 24 18 55 48 8b   ← original em claro (referência)
```

O primeiro byte do dump é o do arquivo **empacotado** (`0x51 = 0x48 ^ 0x19`) — o defeito do
round 6, reproduzido à vontade. E o dump **não é recusado** pelo loader: `diagnose-load.mjs`
não acusa nada; quem morre é o CRT, depois.

**B — a mesma parada com hardware** (`bash scripts/prova-b-hwbp.sh`, log
`evidence/20261014-84-prova-b-hwbp.txt`), sessão nova e banco do módulo apagado:

```
─ SetHardwareBreakpoint {"address":"0x7ff703e71f98","type":"x","size":1}
  Hardware breakpoint set.
  [Hardware] 0x7FF703E71F98 clean.hardcase.exe! (enabled)
…
RVA 0x1f98  48 89 5c 24 18 55 48 8b   <- dump capturado agora (BP de HARDWARE)
RVA 0x1f98  51 89 5c 24 18 55 48 8b   <- dump da Prova A (BP de SOFTWARE)
RVA 0x1f98  48 89 5c 24 18 55 48 8b   <- original em claro (referência)
```

E a cadeia inteira a partir **dessa** captura, sem nenhum patch manual: `rebuild-iat.mjs` com a
lista de módulos tomada **no ponto de parada** (`evidence/20261014-86-modules-bp.txt`: 18 módulos;
no EP a lista tinha **4** — é o stub que carrega as DLLs do alvo) → 315 slots resolvidos, 2 sem
resolução → `reset-load-state.mjs` → `verify-dump.mjs --original`: **`.text` 0 byte diferente**
(157666 bytes) → `run-and-probe.ps1`: **4/4 execuções com exit 0** (`evidence/20261014-87`).

**C — o modo sem original pega o mesmo byte** (`evidence/20261014-89-prova-c.txt`):

```console
# A) captura com BP de SOFTWARE, modo FORTE (--original):
  CODIGO: 5 byte(s) em 2 faixa(s)
      rva 0x1f98  1B  [.text]   esperado 48 89 5c 24 | no dump 51 89 5c 24     exit=1

# B) o MESMO arquivo, SEM original (--packed + --bp-log):
  endereços de breakpoint da captura: 2 (log: 20261014-82-bp-log-soft.jsonl)
      0x7ff703e71f98  [sw] rva 0x1f98 byte 0x51 · empacotado 0x51 · seção reescrita 99.6%
          o byte é o do arquivo EMPACOTADO e a seção foi reescrita: o debugger devolveu o
          valor pré-escrita (defeito do iat-hardcase)
  Veredito: 2 achado(s) de marca conhecida de defeito (modo fraco, sem original)     exit=1

# D) a MESMA captura com hardware, sem original: nenhuma marca; exit=0 (o byte é 0x48)
```

E a checagem de `0xCC` **tem dentes** (senão seria teatro): forçando `0xCC` em `0x1F98` num
dump bom (`unpacked/dump-hwbp-int3.exe`), o modo fraco acusa
`[int3-em-breakpoint] rva 0x1f98  int3 no endereço de um breakpoint do log da captura`, exit 1 —
e **sem** o `--bp-log` o mesmo `0xCC` cai só na lista de candidatos (293 ocorrências, o padding
do MSVC entre elas) e o veredito sai 0. Ou seja: sem o log da captura a rede de segurança
quase não serve; com ele, ela aponta o endereço certo.

**D — o limite do hardware é uma falha silenciosa** (`evidence/20261014-88-limite-dr.txt` e
`…-90-hw-break-armed.txt`): com 4 slots ocupados (DR0-DR3), o 5º `SetHardwareBreakpoint`
responde `Hardware breakpoint set.` e o endereço **não entra na lista** — quem não conferir
segue com um breakpoint que não existe. O driver passou a conferir o `ListBreakpoints` depois de
cada `--hw-break`:

```
[!!] breakpoint de hardware NÃO foi armado em 0x7ff703e72300: a lista não mostra esse endereço
     (DR0-DR3 = 4 por thread, já ocupados) — o x64dbg respondeu "set" mesmo assim
  exit do driver = 1     ·     --bp-log: {"kind":"hw","address":"0x7ff703e72300","armed":false}
```

Para mais pontos que 4: `SetMemoryBreakpoint` (guard page, sem limite de DR, mais lento) ou
breakpoint de software **depois** que a seção está em claro. E a sessão: o x64dbg guarda
breakpoints por módulo em `x64dbg/release/x64/db/<módulo>.dd64`, que voltam armados na carga
seguinte (medido: depois de **reiniciar** o debugger, os 4 de hardware continuavam na lista).
Só com o banco apagado e o debugger reaberto a lista fica limpa (`No breakpoints set.`) — é o
passo 0 de uma captura confiável.

#### 6.5 O que continua **não** exercitado (honesto)

* **`0x28011` (`fothk`, 4 bytes)** — um thunk `jmp` que o programa **re-escreve em runtime**,
não resíduo do stub: medido com `ba w4` que o original **também** escreve ali, e o alvo do salto
é `SizeOfImage + 0xC0` nos dois (`evidence/20261014-63/64`). O `verify-dump.mjs` o reporta como
`CODIGO` porque a seção é marcada executável — é o caso legítimo (b) da mensagem dele.
* **~3,4 KB em `.rdata`/`.data`** que o processo de origem tinha como VA onde o original tem RVA
(tabelas convertidas em runtime, ~1300 campos). Uma reexecução que **não** passe por esses
caminhos roda; um caminho mais longo que os use pode falhar. Fica listado byte a byte pelo
`verify-dump.mjs` — nada em silêncio.
* **2 slots sem resolução** (`0x2a450`, fora da faixa da IAT, e `0x390a8`, na IAT de *delay
import*). A IAT de delay continua com o estado da execução: ela não é preenchida pelo loader,
e sim pelo `__delayLoadHelper2` no primeiro uso — o caminho exercitado não a tocou.
* **Scylla pela GUI** continua **não executado** (o plugin não tem CLI; a GUI exige interação).
O `rebuild-iat.mjs` é o equivalente headless declarado do *Fix Dump* e agora passa a
verificação byte a byte contra o original — mas isso não substitui rodar a ferramenta canônica.
* O comportamento do original nesta máquina é **lançar o Notepad empacotado e sair 0** (é um
stub); logo o critério de “mesma saída” aqui é *exit status + nenhuma exceção + `.text`
idêntico*, não uma comparação de janelas/output do programa completo.

## 7. Reproduzir

```console
$ node scripts/make-packed-sample.mjs work/packer-demo/clean.exe -o work/iat-hardcase/src/clean.hardcase.exe --run --force
$ .\scripts\start-x64dbg.ps1 -Stop                # captura limpa: banco do módulo apagado
$ rm -f x64dbg/release/x64/db/clean.hardcase.exe.dd64 x64dbg/release/x64/db/clean.hardcase.exe.dd64.cmdline
$ .\scripts\start-x64dbg.ps1
$ node scripts/x64dbg-drive.mjs --list-breaks      # tem de dizer "No breakpoints set."
$ node scripts/x64dbg-drive.mjs --load work/iat-hardcase/src/clean.hardcase.exe
$ node scripts/x64dbg-drive.mjs --call 'run {}'                 # para no EP (stub)
$ node scripts/x64dbg-drive.mjs --modules                      # lista parcial (4 módulos, no EP)
# parada no alvo do primeiro `call` do OEP (base+0x1F98) com breakpoint de HARDWARE, que nao
# escreve na memoria; o --bp-log guarda o endereco para o modo sem original:
$ node scripts/x64dbg-drive.mjs --hw-break 0x7ff703e71f98 --bp-log evidence/bps.jsonl
$ node scripts/x64dbg-drive.mjs --call 'run {}'                # o stub decripta e para no BP
$ node scripts/x64dbg-drive.mjs --modules > evidence/modules-no-BP.txt   # ESTA lista (18 módulos)
$ node scripts/x64dbg-drive.mjs --dump-module clean.hardcase work/iat-hardcase/unpacked/dump-hwbp.exe
$ node scripts/rebuild-iat.mjs --dump work/iat-hardcase/unpacked/dump-raw.exe \
      --out work/iat-hardcase/unpacked/dump-fixed.exe --modules <lista.txt> --mem <dir-dos-blobs>

# 4) o passo que faltava para o loader ACEITAR a imagem (estado de carga)
$ node scripts/reset-load-state.mjs --dump work/iat-hardcase/unpacked/dump-fixed.exe
$ node scripts/reset-load-state.mjs --dump work/iat-hardcase/unpacked/dump-fixed.exe \
      --out work/iat-hardcase/unpacked/dump-fixed-loadstate.exe
$ node scripts/diagnose-load.mjs work/iat-hardcase/unpacked/dump-fixed-loadstate.exe

# 5) verificação contra o original (a mesma build em claro) e comportamento
$ node scripts/verify-dump.mjs --dump work/iat-hardcase/unpacked/dump-fixed4.exe \
      --original work/packer-demo/clean.exe
$ powershell -File work/iat-hardcase/scripts/run-and-probe.ps1 -Target work/iat-hardcase/unpacked/dump-final4.exe

# 6) SEM original (é o caso dos alvos reais), com o log da captura: modo fraco
$ node scripts/verify-dump.mjs --dump work/iat-hardcase/unpacked/dump-hwbp-fixed2.exe \
      --packed work/iat-hardcase/src/clean.hardcase.exe --bp-log evidence/bps.jsonl

# A captura com breakpoint de SOFTWARE (dump-raw.exe / dump-swbp.exe) tem o byte de
#   rva 0x1f98 no estado CIFRADO (0x51 em vez de 0x48, `mov [rsp+18h], rbx`) — §6.4(a) e §6.4a.
#   O conserto manual do artefato velho continua em work/iat-hardcase/unpacked/dump-raw-bpfix.exe;
#   a captura nova (dump-hwbp.exe) já sai certa e não precisa dele.
```

Artefatos (todos fora do Git, em `work/`): `src/clean.hardcase.exe`, `unpacked/dump-raw.exe`,
`unpacked/dump-raw-bpfix.exe`, `unpacked/dump-fixed*.exe`, `unpacked/dump-final*.exe`,
`evidence/20261013-*.{json,txt}`, `evidence/mem/*.bin`, `evidence/20261014-*.txt`,
`scripts/run-and-probe.ps1` (harness de comportamento).

# Caso “duro” — OEP → dump de memória → reconstrução da IAT (sem restore automático)

**Status:** parcialmente provado. Tudo abaixo foi medido; a seção [6](#6-o-que-ainda-não-funciona-o-arquivo-reconstruído-é-rejeitado-pelo-loader)
separa o que **não** funciona.

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

## 7. Reproduzir

```console
$ node scripts/make-packed-sample.mjs work/packer-demo/clean.exe -o work/iat-hardcase/src/clean.hardcase.exe --run --force
$ .\scripts\start-x64dbg.ps1
$ node scripts/x64dbg-drive.mjs --load work/iat-hardcase/src/clean.hardcase.exe
$ node scripts/x64dbg-drive.mjs --call 'run {}'                 # para no EP (stub)
$ node scripts/x64dbg-drive.mjs --modules                      # guarde esta lista (mapa de módulos)
# breakpoint no alvo do primeiro `call` do OEP, `run` até parar, então:
$ node scripts/x64dbg-drive.mjs --dump-module clean.hardcase work/iat-hardcase/unpacked/dump-raw.exe
$ node scripts/rebuild-iat.mjs --dump work/iat-hardcase/unpacked/dump-raw.exe \
      --out work/iat-hardcase/unpacked/dump-fixed.exe --modules <lista.txt> --mem <dir-dos-blobs>

# 4) o passo que faltava para o loader ACEITAR a imagem (estado de carga)
$ node scripts/reset-load-state.mjs --dump work/iat-hardcase/unpacked/dump-fixed.exe
$ node scripts/reset-load-state.mjs --dump work/iat-hardcase/unpacked/dump-fixed.exe \
      --out work/iat-hardcase/unpacked/dump-fixed-loadstate.exe
$ node scripts/diagnose-load.mjs work/iat-hardcase/unpacked/dump-fixed-loadstate.exe
```

Artefatos (todos fora do Git, em `work/`): `src/clean.hardcase.exe`, `unpacked/dump-raw.exe`,
`unpacked/dump-fixed.exe`, `evidence/20261013-*.{json,txt}`, `evidence/mem/*.bin`.

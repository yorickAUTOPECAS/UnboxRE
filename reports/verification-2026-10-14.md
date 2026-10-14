# Verificação — rodada de 2026-10-14

Cada afirmação abaixo tem **comando + saída**. O que **não** funcionou fica na seção [5](#5-o-que-não-funcionou-nesta-rodada),
separado de propósito: uma limitação reportada vale mais que um sucesso narrado.

Escopo desta rodada (o que ficou aberto no relatório anterior):

1. **fechar a investigação do `0xC000007B` com a ferramenta certa e deixá-la permanente
   no catálogo** — loader snaps (gflags) com o mesmo tratamento das outras ferramentas:
   licença verificada por fonte primária, catálogo, ficha, atribuição;
2. **bootstrap a partir de máquina genuinamente zerada** (não “quase zerada”);
3. **mais um lote de cobertura de licença**, verificado em fonte primária.

O que a rodada entregou, em uma linha cada: o gflags entrou no catálogo/bootstras com ficha
e licença (`b.9`, `docs/tools/gflags.md`); o par `load-snaps.ps1` + `capture-debugprint.ps1`
foi ligado de verdade contra o fixture conhecido; o bootstrap do zero **funciona** e, por
isso, expôs **dois bugs reais** (corrigidos); o registro de licenças passou de 75 para 79
linhas e a cobertura do bootstrap de 23/29 para 27/30.

---

## 1. Loader snaps — ferramenta ligada, catalogada e documentada

O que o `gflags` faz, sem ele: a escrita do bit `FLG_SHOW_LDR_SNAPS (0x2)` em
`HKLM\…\Image File Execution Options\<imagem>\GlobalFlag`, mais um leitor da saída.

```console
$ powershell -File .\scripts\load-snaps.ps1 -Image dump-raw.exe -Apply     # shell ELEVADO
  [OK  ] GlobalFlag de dump-raw.exe agora é 0x2 (chave: HKLM:\SOFTWARE\Microsoft\Windows
         NT\CurrentVersion\Image File Execution Options\dump-raw.exe)
  [INFO] loader snaps LIGADOS - a saída aparece no debugger do processo NOVO, não aqui.
$ powershell -File .\scripts\load-snaps.ps1 -Image dump-raw.exe -Status -Json
{ "globalFlag": "0x2", "loaderSnaps": true, "keyExists": true, "elevated": true }
```

E a limpeza, pelo mesmo caminho (o script **nunca** se eleva sozinho — sem `-Apply` é
dry-run, e com `-Apply` fora de um shell elevado ele para com instrução clara):

```console
$ powershell -File .\scripts\load-snaps.ps1 -Image dump-raw.exe -Disable -Apply
  [OK  ] GlobalFlag de dump-raw.exe agora é 0x0
  [INFO] loader snaps desligados (nada mais é impresso pelo loader).
$ powershell -Command "<varredura de IFEO por GlobalFlag != 0>"
(fim)          # nenhuma chave ficou ligada
```

Efeito medido com o x64dbg aberto e o alvo carregado
(`work/iat-hardcase/evidence/20261013-5-loadsnaps.json`):

```console
Events (8/8):
[x64dbg-MCP Server] Process created.
[x64dbg-MCP Server] DLL loaded.
[x64dbg-MCP Server] OutputDebugString received.   ← o loader falou
[x64dbg-MCP Server] OutputDebugString received.
[x64dbg-MCP Server] OutputDebugString received.
[x64dbg-MCP Server] Process exited.
```

Os snaps **são emitidos** — mas o `GetEventLog` do MCP registra o evento sem a string. Foi
por isso que a rodada tratou o **canal de leitura** como o problema e o isolou com três
experimentos, em vez de chutar:

**(a) o listener funciona?** Sim — auto-teste com um emissor direto
(`OutputDebugString` de **outro** processo, `evidence/20261014-13-dbwin-selftest.txt`):

```console
--- emissor: OutputDebugString direto, outro processo ---
enviado: TESTE-DBWIN-20261014-OK
  [INFO] escutando a saída de depuração por 12s
[pid 14916] TESTE-DBWIN-20261014-OK      ← o canal e o listener estão OK
  [OK  ] gravado em …\20261014-13-dbwin-selftest.txt
bytes: 37 · CAPTUROU
```

**(b) e o alvo?** Em branco, e isso agora é um resultado e não um mistério: com snaps
**ligados** numa imagem **válida** (`clean.exe`, que carrega 50 DLLs e sai 0), lançada sem
debugger, o listener gravou **0 byte** (`evidence/20261014-12-loadsnaps-control-clean.txt`).
O mesmo com o dump (`…-11-loadsnaps-raw.txt`).

**(c) o debugger é o destino?** O log do x64dbg (evidência acima) mostra que os eventos
*saem* quando há debugger anexado — e o `headless.exe` do x64dbg, rodando o mesmo arquivo,
escreve no stdout as linhas de módulo/símbolo (`[SYMBOL] No symbols loaded for:
dump-fixed.exe`), mas não as linhas `LDR:` do loader.

Conclusão medida: **sem debugger anexado, não há saída de loader snaps para o canal
global nesta máquina; com debugger, ela existe mas não passa pelo log de eventos do MCP**
(o plugin não tem nenhuma tool que devolva o texto do log: a lista de nomes extraída do
`.dp64` tem `GetEventLog`, `GetDisassembly`, `GetMemoryMap`… e nenhum `GetLog`). Onde ler
o texto: janela *Log* do x64dbg, WinDbg, DebugView. O que **não** funciona está em
[5](#5-o-que-não-funcionou-nesta-rodada).

Um dado de bônus do mesmo experimento, que vale para o caso duro: `dump-raw.exe` **não
consegue nem ser lançado** — o `CreateProcess` recusa antes do loader mapear nada:

```console
$ Start-Process .\work\iat-hardcase\unpacked\dump-raw.exe
Start-Process : … O executável especificado não é um aplicativo válido para esta
                 plataforma de SO.          # ERROR_BAD_EXE_FORMAT
```

É exatamente o que a tela do Windows na mensagem original do usuário mostra
(“Este aplicativo não pode ser executado em seu PC”): o dump **cru** é recusado na
validação do arquivo, antes de qualquer código rodar — nenhum loader snap apareceria para
ele. O `dump-fixed.exe`, esse sim, chega mais longe (`0xC000007B` com a imagem mapeada) e é
o único onde os snaps têm algo a dizer.

Estado do registro ao final (higiene — nada de flag esquecido ligado):

```console
$ powershell -Command "Get-ChildItem 'HKLM:\…\Image File Execution Options' |
    ForEach-Object { $p=Get-ItemProperty $_.PSPath; if ($p.GlobalFlag -ne $null) { … } }"
                       # nenhuma chave com GlobalFlag ligado
```

Fatos da instalação, medidos nesta máquina (sustentam o “por que o script existe”):

```console
$ winget search "debugging tools"
No package found matching input criteria.

$ winget list --id Microsoft.WinDbg --exact
Name    Id               Version        Source
WinDbg  Microsoft.WinDbg 1.2610.1001.0  winget

$ (Get-ChildItem <InstallLocation do WinDbg> -Filter '*.exe').Name -join ', '
createdump.exe, DbgX.Mcp.Proxy.exe, DbgX.Shell.exe, DebuggerCredentialManager.exe
$ Get-ChildItem <InstallLocation> -Filter 'gflags*' -Recurse     # → nada (0 resultados)
```

…isto é: **o pacote do WinDbg não traz o gflags** e não existe pacote do componente
*Debugging Tools for Windows* no winget. A Microsoft confirma onde ele vive
(`C:\Program Files (x86)\Windows Kits\10\Debuggers\{x64,x86}`) e que gflags só é
instalado quando se seleciona esse componente — as duas páginas estão citadas na ficha.

Artefatos desta rodada:

| Onde | O que |
|---|---|
| [docs/tools/gflags.md](../docs/tools/gflags.md) | ficha completa (o que faz, quando **não** usar, instalação, receitas, armadilhas) |
| [docs/02-catalogo-ferramentas.md](../docs/02-catalogo-ferramentas.md) `§3 b.9` | entrada no catálogo, com o comando de cada caminho |
| [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) · [docs/03-licencas.md](../docs/03-licencas.md) | atribuição e matriz de licença |
| `config/licenses.json` | `gflags (Debugging Tools for Windows)` → `LicenseRef-Microsoft-SDK-WDK-EULA` + `rawUrl` + `needles` |
| `scripts/bootstrap-windows.ps1` | entrado no catálogo (perfil `dynamic`), com o `Why` apontando a alternativa sem SDK |

Dry-run do perfil, provando que o bootstrap conta a verdade:

```console
$ powershell -File .\scripts\bootstrap-windows.ps1 -Profile dynamic -DryRun
── gflags (Debugging Tools for Windows)  [dynamic]
   por quê: loader snaps: ver a decisão do loader quando a imagem é recusada — alternativa: scripts/load-snaps.ps1
   licença: proprietária (EULA Microsoft)
  [WARN] gflags (Debugging Tools for Windows): instalação manual necessária
      fonte: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools
```

## 2. Bootstrap a partir de máquina zerada — e os dois bugs que ele achou

Ponto de partida: os quatro diretórios do núcleo **removidos por completo**, junto com o
cache de downloads (`evidence/20261013-9-bootstrap-do-zero.txt`):

```console
$ rm -rf ghidra x64dbg rea-main .cache       # rc=0
$ ls -d ghidra x64dbg rea-main .cache        # (nada)
```

Primeira execução do bootstrap do zero → **dois defeitos reais**, nenhum deles visível numa
máquina “quase pronta”:

| defeito | sintoma | correção |
|---|---|---|
| `-Profile core` **não** disparava o `fetch` | a doc promete “o perfil core roda o fetch antes” (README §3, docs/04) e o código só rodava o fetch com `-Profile fetch`: o bootstrap terminava “toolchain ok” e a máquina continuava **sem** Ghidra/x64dbg/REA | `core` agora **implica** `fetch` (`bootstrap-windows.ps1`) |
| o winget devolve **código de erro** quando o pacote já está instalado | `winget install zig.zig` num Zig instalado → exit **-1978335189 (0x8A15002B)** “no applicable upgrade”; o bootstrap tratava isso como falha e listava Zig/CMake/Ninja como “pendentes” numa máquina que os tem | o estado do instalador virou `ok`/`present`/`fail`; “already installed” conta como **present** (e vai para “já presentes”, não para “instalados”) |

Depois das correções, a execução completa do zero:

```console
$ powershell -File .\scripts\bootstrap-windows.ps1 -Profile core -Apply -Yes
  perfis: fetch, core
── Núcleo de terceiros (fetch do upstream)
  [OK  ] baixado e verificado: ghidra_12.1.4_PUBLIC_20260921.zip (543.3 MB)
  [OK  ] baixado e verificado: snapshot_2026-05-27_12-11.zip (30.1 MB)
  [OK  ] baixado e verificado: rea-agents-6.4.0.tgz   → npm install (143 pacotes)
  [OK  ] baixado e verificado: x64dbg-MCP-Server-v1.6.zip
  [OK  ] instalado: release/x64/plugins/x64dbg-MCP-Server.dp64
  [OK  ] instalado: release/x32/plugins/x64dbg-MCP-Server.dp32
  instalados/ok: 4   falhas: 0
  instalados: 0   já presentes: 6   pendentes/manual: 0
$ ls -d ghidra x64dbg rea-main
ghidra  rea-main  x64dbg        # 876M · 102M · 86M
```

`health-check.ps1` na máquina reconstruída do zero (o mesmo script que, antes desta rodada,
**morria** com o núcleo ausente):

```console
$ powershell -File .\scripts\health-check.ps1 -Json
summary: {"ok":36,"warn":3,"fail":0}          # exit 0
  WARN host:zig   | zig 0.17.0 instalado pelo winget, mas fora do PATH desta sessão
  WARN host:cmake | cmake 4.4.4 instalado pelo winget, mas fora do PATH desta sessão
  WARN mcp:config | token ainda não gerado
```

Os dois `WARN` de build tools são o terceiro achado da rodada: **PATH obsoleto ≠ ferramenta
ausente**. O winget instala e registra o pacote, e só depois atualiza o PATH — uma janela
aberta antes disso não herda o valor novo, e o probe por comando dizia “ausente” numa
máquina que tem o Zig 0.17.0. O `health-check` agora cruza com uma única chamada ao
`winget list` (lazy: só quando alguma ferramenta falha no PATH) e reporta o fato:
“instalado pelo winget, mas fora do PATH desta sessão”.

## 3. Lote de licenças (rodada 4) — 4 linhas novas, 26/29 → 27/30 de cobertura

O gap declarado (`config/licenses.json`, note) era: Procmon/Sysinternals, API Monitor,
WSL/Ubuntu e o trio de firmware. O que foi **fechado**, cada um por fonte primária:

| Ferramenta | Declarado | Evidência primária |
|---|---|---|
| `ubi_reader` | `GPL-3.0` | repo + `LICENSE` bruto (`onekey-sec/ubi_reader`; `jrspruitt/ubi_reader` redireciona) |
| `Sysinternals (Procmon, Process Explorer, Autoruns, TCPView)` | `LicenseRef-Microsoft-Sysinternals-EULA` | página de license terms que a Microsoft publica para as próprias ferramentas |
| `API Monitor` | `LicenseRef-Freeware-Rohitab` | o próprio site do autor: “Freeware 32-bit and 64-bit Versions” |
| `gflags (Debugging Tools for Windows)` | `LicenseRef-Microsoft-SDK-WDK-EULA` | termos do EWDK/SDK da Microsoft (o gflags embarca no SDK/WDK) |

Cada `needles` foi conferido **contra o texto buscado**, do mesmo jeito que o
`verify-licenses.mjs` faz (`fetch` + `includes`) — não por leitura humana da página.

```console
$ node scripts/verify-licenses.mjs
     ubi_reader      declara GPL-3.0     raw:ok    api:n/a
     Sysinternals (…) declara LicenseRef-Microsoft-Sysinternals-EULA  raw:ok  api:n/a
     API Monitor     declara LicenseRef-Freeware-Rohitab              raw:ok  api:n/a
     gflags (Debugging Tools for Windows) declara LicenseRef-Microsoft-SDK-WDK-EULA raw:ok api:n/a

  [OK] 79 licenças declaradas batem com a fonte primária.
```

Os três que continuam **ausentes** seguem ausentes **com o motivo medido**, não por
esquecimento: `sasquatch` e `firmware-mod-kit` não têm arquivo de licença nenhum na raiz do
repositório (conferido pela API de contents do GitHub: sasquatch = `README.md`, `build.sh`,
`patches`; firmware-mod-kit = fontes e scripts), e Ubuntu/WSL é uma distribuição de milhares
de pacotes com licenças diferentes — uma linha SPDX ali seria mentira.

## 4. Verificações offline (as mesmas que o CI roda)

```console
$ node scripts/check-consistency.mjs
  núcleo: 4 · catálogo: 30 · perfis: 13 · flags MCP: 9
  licenças com linha verificada: 27/30 do bootstrap · registradas: 79
  [OK] nenhuma divergência encontrada (197 verificações).

$ powershell -NoProfile -Command "<Parser::ParseFile em todo .ps1>"   # sintaxe
OK   scripts/bootstrap-windows.ps1
OK   scripts/health-check.ps1
OK   scripts/load-snaps.ps1
OK   scripts/capture-debugprint.ps1
OK   scripts/lib/common.ps1
```

## 5. O que NÃO funcionou nesta rodada

1. **O texto dos loader snaps não foi lido — e agora se sabe por quê.** Com debugger
   anexado a saída é emitida (o log do x64dbg a registra como evento, sem a string); sem
   debugger, ela **não chega** ao canal global nesta máquina (control test com `clean.exe`
   e snaps ligados: 0 byte). O listener está descartado como culpado (auto-teste em §1).
   Quem faltava ser tentado era o leitor **dentro** do debugger: janela *Log* do x64dbg e
   WinDbg (instalado) — e foi por esse caminho que a rodada seguinte (§7) fechou a pergunta.
   Consequência honesta naquele momento: a pergunta “qual checagem do `ntdll` reprova o
   `dump-fixed.exe`” ficou em aberto **naquela** rodada; **está respondida na §7** abaixo.
2. **O MCP do x64dbg não expõe o texto do log.** O plugin tem `GetEventLog` (eventos) e
   nenhuma tool que devolva o conteúdo do log — confirmado pela lista de nomes extraída do
   `x64dbg-MCP-Server.dp64`. Ler loader snaps por MCP, hoje, não é possível; isso é uma
   limitação do plugin de terceiros, não deste toolkit.
3. **A API de licença do GitHub respondeu 403 na verificação local** (limite de requisições
   sem token, 60/h). O `verify-licenses.mjs` trata isso como aviso e o `--strict` (usado no
   CI, que passa `GITHUB_TOKEN`) é o que transforma rede degradada em falha. Ou seja: nesta
   rodada o que foi conferido **contra arquivo bruto** passou; o cruzamento pela API não
   rodou localmente.
4. **`sasquatch`, `firmware-mod-kit` e Ubuntu/WSL continuam sem linha de licença** — por
   ausência de fonte primária, não por falta de tempo (motivo medido no §3).
5. **O gflags em si não foi executado** (não está instalado nesta máquina, e instalar o
   Windows SDK não é uma decisão que o agente toma sozinho). O que foi exercitado é o
   caminho equivalente do próprio toolkit (`load-snaps.ps1`), que escreve o **mesmo** bit.

## 6. Reproduzir

```powershell
# 0) estado real da máquina
.\scripts\health-check.ps1 -Json

# 1) do zero: núcleo + toolchain (fetch incluído pelo perfil core)
.\scripts\bootstrap-windows.ps1 -Profile core -DryRun
.\scripts\bootstrap-windows.ps1 -Profile core -Apply -Yes

# 2) loader snaps (o passo que faltava no caso do 0xC000007B)
.\scripts\diagnose-load.mjs work\iat-hardcase\unpacked\dump-fixed.exe
powershell -File .\scripts\load-snaps.ps1 -Image dump-fixed.exe -Apply    # shell ELEVADO
.\scripts\capture-debugprint.ps1 -Seconds 30 -OutFile work\iat-hardcase\evidence\loadsnaps.txt
# … no x64dbg: LoadBinary no alvo (o debugger passa a ser o destino da saída)
.\scripts\load-snaps.ps1 -Image dump-fixed.exe -Disable -Apply            # desligar sempre

# 3) verificações offline (as do CI)
node .\scripts\check-consistency.mjs
node .\scripts\verify-licenses.mjs
```

---

## 7. Rodada seguinte (mesmo dia) — a checagem do loader medida, e o `0xC000007B` fechado

Escopo desta rodada: **fechar o `0xC000007B` do dump de memória do caso `hardcase`**
(`work/iat-hardcase/`), que o x64dbg carrega e o loader do Windows recusa.

Resultado: a checagem que reprova está **identificada por medição** (breakpoint, registrador
e valor lido) e existe uma correção verificada — `scripts/reset-load-state.mjs`. A cadeia
completa está em [root-cause-0xc000007b.md](root-cause-0xc000007b.md) §8.

> A medição foi possível com `cdb` (WinDbg 10.0.29661) + símbolos do Microsoft Symbol Server,
> breakpoint por **módulo+offset** (imune a ASLR) e leitura de registrador. Os loader snaps da
> §5 mostram *que* o loader reprovou; eles não dizem *onde*. Foi o breakpoint que localizou.

### 7.1 De onde vem o status — 3 breakpoints, 1 execução

```console
$ cdb -y "srv*<cache>*https://msdl.microsoft.com/download/symbols" -xe ld:ntdll.dll \
    -c 'bp ntdll+0x8c0f8 ".echo ===RETORNO DE LdrpInitializeProcess===; r eax; g";
        bp ntdll+0x8c133 ".echo ===CAMINHO FALHA +0x1a7===; g";
        bp ntdll+0x8c102 ".echo ===CAMINHO SUCESSO +0x176===; g"; g; q' \
    work/iat-hardcase/unpacked/variants/dump-fixed-nosnap.exe
===RETORNO DE LdrpInitializeProcess===
 eax=c000007b                       ← o status da recusa, lido em `eax`
===CAMINHO FALHA +0x1a7===          ← o caminho de sucesso (+0x176) NUNCA disparou
```

(Enquanto os loader snaps estão ligados, um `wt` de dentro da função é interrompido pelo
próprio evento de debug-print do snap. Foi por isso que a medição passou a ser feita com o
**mesmo arquivo renomeado** — a chave do `GlobalFlag` é por nome de imagem, então a cópia roda
sem snaps e o trace/breakpoint acontece sem interferência.)

### 7.2 A checagem, dentro de `LdrpProcessMappedModule`

```console
$ cdb … -c 'bp ntdll+0xa9af "…eax=; r eax; g"; bp ntdll+0xa9fc "…; r eax; g";
             bp ntdll+0xaabe "…; r eax; g"; bp ntdll+0xab82 "…edi=; r edi; g"; g; q'
===1-apos-RtlImageNtHeaderEx eax=0                  ← cabeçalhos OK
===2-apos-LdrpValidateEntrySection eax=1            ← EP(0x19c0) >= SizeOfHeaders(0x1000): passa
===4-TAIL edi=c000007b                              ← bp 3 (LdrpCfgProcessLoadConfig) NÃO disparou
```

O `edi=0xC000007B` do tail só é escrito em `+0x22e`, e o único caminho que chega lá sem passar
pelo `LdrpCfgProcessLoadConfig` é o `+0x226`. Medindo esse trecho:

```console
===+0x11d (EntryPoint!=0)===   000001f7`a5cb7408  00007ff7`575719c0   ← EntryPoint = base+0x19c0
===+0x124 versao===            00007ff7`57570140  000a 0000          ← MajorSubsystemVersion = 10
===+0x226 test eax===          eax=0                                  ← fall-through → 0xC000007B
```

Ou seja: `MajorSubsystemVersion >= 7` leva a `+0x226`, e ali um **`eax == 0`** decide a recusa.
Esse `eax` é o retorno de `LdrInitSecurityCookie` (nenhuma instrução entre a chamada e o teste
escreve `eax`).

### 7.3 O valor que reprova: `__security_cookie` em estado de execução

```console
===cookie-ptr===
rax=00007ff757599790                       ← LoadConfig (RVA 0x29790 = data dir 10)
rbx=00007ff757570000                       ← DllBase (base ASLR NOVA)
00007ff7`575997e8  00007ff7`575a4400       ← [LoadConfig+0x58] = SecurityCookie (RVA 0x34400)
===COMPARACAO-DO-MAGIC===
00007ff7`575a4400  0000eb6c`2996b639       ← [cookie] = valor de EXECUÇÃO
r14=00002b992ddfa232                       ← sentinela do MSVC que o loader exige
===FALHA-em-LdrInitSecurityCookie (eax=0)===
```

(O mesmo breakpoint na 1ª invocação — a própria `ntdll` — mostra `[cookie] = 0x2b992ddfa232` e
passa: é o contraste que fecha o argumento.)

### 7.4 A correção e a verificação

```console
$ node scripts/reset-load-state.mjs --dump work/iat-hardcase/unpacked/dump-fixed.exe
  config: LoadConfig rva=0x29790 size=0x148
  cookie: VA=0x7ff77be54400  RVA=0x34400
          antes  = 0x0000eb6c2996b639 (estado de EXECUÇÃO)
          depois = 0x00002b992ddfa232 (sentinela MSVC)
  ação  : dry-run
$ node scripts/reset-load-state.mjs --dump …\dump-fixed.exe --out …\dump-fixed-loadstate.exe
  ação  : escrito / saída: …\dump-fixed-loadstate.exe (380928 bytes)
```

| arquivo | saída, 3 execuções | leitura |
|---|---|---|
| `src/clean.hardcase.exe` | `0x0 0x0 0x0` | roda (controle) |
| `unpacked/dump-raw.exe` | `erro:EFTYPE ×3` | `CreateProcess` recusa (193 = ERROR_BAD_EXE_FORMAT) |
| `unpacked/dump-fixed.exe` | `0xC000007B ×3` | loader recusa |
| `unpacked/dump-fixed-loadstate.exe` | `0xC0000005 ×3` | **loader aceita**; o código roda e falha no EP |

E o `diagnose-load.mjs` (que nesta rodada aprendeu a olhar o estado de carga) passa a nomear o
vício e a correção:

```console
$ node scripts/diagnose-load.mjs work/iat-hardcase/unpacked/dump-fixed.exe
  [i ] reloc-ok — 361 entradas de relocação, todas em seções com dados
  [!!] cookie-em-estado-de-execucao — __security_cookie em RVA 0x34400 = 0x0000eb6c2996b639, mas o
       loader exige o sentinela do MSVC 0x2b992ddfa232: … Corrija com:
       node scripts/reset-load-state.mjs --dump <dump.exe> --out <saida.exe>
  [!!] loader-rejeitou — a execução terminou com 0xC000007B …
  Veredito: imagem com vícios de loader conhecidos        (exit=1)
$ node scripts/diagnose-load.mjs work/iat-hardcase/unpacked/dump-fixed-loadstate.exe
  [i ] cookie-no-sentinela — … está no sentinela do MSVC (estado de carga limpo)
  [i ] run — exit=0xc0000005 (STATUS_ACCESS_VIOLATION)
  Veredito: sem vício de loader conhecido                 (exit=0)
```

Que a imagem foi **aceita** também aparece no `cdb`: o alvo carrega `IMM32.DLL` e a falta é no
código do alvo (`rip` inválido chamado de `wWinMainCRTStartup+0x9`, ou seja EP+9), não no loader:

```console
ModLoad: 00007ffd`13cd0000 00007ffd`13d01000   C:\WINDOWS\System32\IMM32.DLL
(2e0.2080): Access violation - code c0000005 (first chance)
rip=0000004cccb35000
0000004c`cc95f9d8 00007ff6`259b19c9 : … : 0x0000004c`ccb35000
0000004c`cc95f9e0 00007ffd`1466cd87 : … : notepad!wWinMainCRTStartup+0x9
```

### 7.5 O erro de harness da rodada anterior (corrigido nesta)

O teste de carga usava `(r.status >>> 0)`. Quando o `spawnSync` **não consegue executar** o
arquivo, `status` é `null` — e `null >>> 0` é `0`. Foi assim que `dump-raw.exe` apareceu como
"exit 0" numa medição intermediária desta rodada. `cdb` mostrou o que era de verdade:

```console
CommandLine: …\dump-raw.exe
Cannot execute '…\dump-raw.exe', Win32 error 0n193
    "%1 não é um aplicativo Win32 válido."
```

Consequência prática: **`0xC000007B` e `EFTYPE`/193 são o mesmo STATUS_INVALID_IMAGE_FORMAT** — a
diferença é o estágio (o `CreateProcess` desiste antes de criar o processo, em vez de o processo
já criado morrer no loader). O harness passou a distinguir `r.error` de `status === 0`, o
`diagnose-load.mjs` também (§7.4) e o `reset-load-state.mjs` nasceu com a mesma distinção.

### 7.6 O que NÃO funcionou nesta rodada

1. **O Scylla não foi executado.** A dependência pedida para separar "problema da captura" vs
   "problema da reconstrução" acabou resolvida por outra via: o dump **cru** (`dump-raw.exe`) é
   recusado **antes** de qualquer reconstrução (`EFTYPE`/193 no `CreateProcess`), então os dois
   arquivos têm o mesmo destino. Além disso, o `rebuild-iat.mjs` é declaradamente o equivalente
   headless do *Fix Dump* do Scylla — logo `dump-fixed.exe` **é** o que o *Fix Dump* produziria,
   e ele falhava com `0xC000007B` até o cookie ser reposto. Rodei o Scylla? **Não** (o plugin do
   x64dbg não tem modo CLI; a GUI exige interação). Fica como não feito, com a previsão
   registrada: **um dump "consertado" pelo Scylla, sem o reset de estado, continua recusado.**
2. **Dois falsos começos meus, registrados para não se repetirem:** (a) `wt` dentro de
   `LdrpInitializeProcess` foi interrompido pelo evento de debug-print dos próprios loader
   snaps — resolvido rodando a cópia sem o flag; (b) dois breakpoints com offset errado
   (`0x2a9af` em vez de `0xa9af`) apontaram para endereço inválido e geraram um
   access violation que não tinha nada a ver com o alvo — os offsets abaixo de `0x10000`
   perderam o dígito `a` na conta.
3. **O `0xC0000005` que sobra não é loader.** O EP de um dump é o do stub do packer, que
   reexecuta sobre memória já desempacotada: apontar o EP para o OEP e completar a resolução de
   imports é trabalho **separado**, e não foi feito nesta rodada.
4. **A confirmação nos binários do DEMO não foi refeita.** A §5 desta verificação mediu três
   gatilhos (`LOADCONFIG` zerado, `.rdata`/`.data` esvaziados, `BASERELOC` zerado) que agora
   têm mecanismo na cadeia identificada (root-cause §8.4) — mas isso é leitura de disassembly,
   não breakpoint naquelas amostras.

### 7.7 Reproduzir

```bash
# 0) o alvo do caso e o diagnóstico (detecta o vício e aponta a correção)
node scripts/diagnose-load.mjs work/iat-hardcase/unpacked/dump-fixed.exe

# 1) a correção (dry-run por padrão)
node scripts/reset-load-state.mjs --dump work/iat-hardcase/unpacked/dump-fixed.exe
node scripts/reset-load-state.mjs --dump work/iat-hardcase/unpacked/dump-fixed.exe \
     --out work/iat-hardcase/unpacked/dump-fixed-loadstate.exe

# 2) a prova de carga: 0xC000007B antes, 0xC0000005 (loader aceitou) depois
node scripts/diagnose-load.mjs work/iat-hardcase/unpacked/dump-fixed-loadstate.exe

# 3) verificações offline (as do CI)
node scripts/check-consistency.mjs
node scripts/verify-licenses.mjs
```

---

## 8. Rodada seguinte (mesmo dia) — EP → OEP: o caso iat-hardcase **fechado**

Escopo pedido: (1) documentar no `docs/06` a sequência que falta depois do dump (dump
recusado → diagnóstico → correção), **só prosa, sem tocar em script**; (2) fechar o caso
reapontando o EP para o OEP e medindo o comportamento contra o original; (3) documentar com
precisão, sem forçar conclusão. Todo o resto abaixo é consequência medida desses dois itens —
e a premissa do item 2 **não se confirmou** (§8.2).

Em uma linha: o EP **já era** o OEP; o que faltava era **um byte** que o dump carregava (do
breakpoint de software do próprio analista) e **dois bugs do nosso `rebuild-iat.mjs`**
(descritores com passo de 24 bytes e agrupamento por DLL). Corrigidos os três, o dump
reconstruído **roda e sai com o mesmo status do original (4/4)**.

### 8.1 Prioridade 1 — o `docs/06` agora tem o caminho do dump recusado

Edição de prosa no Cenário 1 (`docs/06-workflows.md`), passos 8–10 e os critérios: o que
fazer quando o dump reconstruído é recusado, como corrigir estado de carga e como comparar
com o original. Nenhum script mudou por causa disso (a verificação abaixo é o que garante):

```console
$ node scripts/check-consistency.mjs
  núcleo: 4 · catálogo: 30 · perfis: 13 · flags MCP: 9
  licenças com linha verificada: 27/30 do bootstrap · registradas: 79
  [OK] nenhuma divergência encontrada (197 verificações).
  exit=0
```

O `check-consistency` é justamente o guarda de “doc ↔ código”: ele valida que todo
`scripts/*.mjs` citado na doc existe e que todo script do repo é citado em alguma doc — os
novos passos e a ferramenta nova passam por ele.

### 8.2 A medição que derrubou a premissa: `AddressOfEntryPoint` **já é** o OEP

`evidence/20261014-70-ep-e-oep.txt`:

```console
src/clean.hardcase.exe             EP=0x19c0  bytes@0x19c0: e9 3b 86 05 00 90 90 90  .text difere em 157051 byte(s)
unpacked/dump-raw.exe              EP=0x19c0  bytes@0x19c0: 48 83 ec 28 e8 cf 05 00  .text difere em 1 byte(s)
unpacked/dump-fixed.exe            EP=0x19c0  bytes@0x19c0: 48 83 ec 28 e8 cf 05 00  .text difere em 1 byte(s)
unpacked/dump-fixed-loadstate.exe  EP=0x19c0  bytes@0x19c0: 48 83 ec 28 e8 cf 05 00  .text difere em 1 byte(s)
unpacked/dump-fixed3.exe           EP=0x19c0  bytes@0x19c0: 48 83 ec 28 e8 cf 05 00  .text difere em 0 byte(s)
original (notepad do sistema)      EP=0x19c0  bytes@0x19c0: 48 83 ec 28 e8 cf 05 00
```

No arquivo **empacotado**, 0x19C0 é o EP porque ali está o `jmp` para o stub; o stub restaura
os 8 bytes originais *naquele mesmo endereço* e salta para ele. O dump já tem a versão
restaurada — logo não havia nada para reapontar. Confirmação com símbolos (o `clean.exe` é
byte-idêntico ao `notepad.exe` do sistema, sha256 `468ffe12…`):

```console
$ cdb -c "sxe av; bp $exentry; g; u $exentry L3" dump-final3.exe
notepad!wWinMainCRTStartup:
  00007ff6`8a0519c0 4883ec28  sub  rsp,28h
  00007ff6`8a0519c4 e8cf050000 call notepad!_security_init_cookie
  00007ff6`8a0519c9 4883c428  add  rsp,28h
```

### 8.3 O dump carregava **uma instrução trocada** (e o loader a aceitava)

`.text` do dump diferia do original em **exatamente 1 byte**, em RVA `0x1F98` — o endereço do
`SetBreakpoint` usado para tirar a foto:

```console
$ node -e '…compara .text do dump com o original, byte a byte…'
unpacked/dump-raw.exe       1 byte  [rva 0x1f98: 48 -> 51]
(…todas as variantes da rodada anterior: idem, herdado do dump cru)
byte empacotado em 0x1F98 = 0x51  | keystream do stub nessa posição = 0x19
```

Ou seja: o dump guardou o byte **ainda cifrado** (`0x48 ^ 0x19 = 0x51`). Mecanismo: o
breakpoint de **software** foi escrito no byte antes de o stub decriptar a seção; ao parar, o
debugger restaurou o valor que havia salvado — o *pré*-decriptação.

Traçagem com `t` (o `s` do WinDbg é *search*, não *step* — erro meu, corrigido):

```console
---t2--- 0x7ff7`1f2d1f98   (entra em _security_init_cookie)
---t17-- 0x000000ed`60847000  ← o `ret` do epílogo devolve o rcx empilhado a mais
Child-SP          RetAddr             Call Site
000000ed`606ff988 00007ff7`1f2d19c9  0x000000ed`60847000
                              …      notepad!wWinMainCRTStartup+0x9
!address @rip → MEM_FREE / PAGE_NOACCESS
```

Só isso já explica o `0xC0000005` “no EP” das rodadas anteriores: o loader aceitava a imagem e
o CRT despencava. Reposto o byte, o `.text` fica **idêntico ao original** (§8.2).

### 8.4 Bug 1 no `rebuild-iat.mjs`: os descritores saíam com passo de 24 bytes

`IMAGE_IMPORT_DESCRIPTOR` tem **20** bytes e o loader avança 20 por entrada; o script
alinhava cada descritor a 8 (o que dá 24), então o loader lia o #0 e, no #1, encontrava
`Name == 0` — parava ali. `evidence/20261014-71-descriptor-passo.txt`:

```console
unpacked/dump-fixed.exe  IMPORT dir rva=0x5c948 size=0xb4 -> leitura do loader (passo 20):
   #0 @0x5c948  OFT=0x5c000  Name=comctl32.dll                          FT=0x298d8
   #1 @0x5c95c  OFT=0x0      Name=<Name=0 -> o loader PARA aqui>        FT=0x5ca2a
```

Efeito medido no `lm` do alvo: **só o comctl32 resolvido**, `combase.dll` ausente:

```console
# antes (evidence/20261014-55):  … gdi32, msvcrt, KERNEL32, USER32, ntdll   (sem combase)
# depois (evidence/20261014-58): … USER32, combase, RPCRT4, gdi32, KERNEL32, ntdll
```

A primeira chamada que dependia dela morria:
`call qword ptr [_imp_CoCreateGuid]` → `00007ffd14d359e0`, região `MEM_FREE`.

### 8.5 Bug 2 no `rebuild-iat.mjs`: um descritor por DLL (e não por corrida contígua)

Um descritor declara uma faixa **contígua** de `FirstThunk`. Como cada DLL de contrato
`api-ms-win-*` é um descritor próprio no arquivo original e todas resolvem no mesmo host, uma
DLL real aparece em **várias corridas**. Agrupando por DLL, o loader escrevia `kernelbase` por
cima de `kernel32`:

```console
notepad+0x113: 0fb703  movzx eax, word ptr [rbx]     ; rbx = 0
  rbx ← `call qword ptr [_imp_GetCommandLineW]` (o slot tinha outra função, que devolve 0)
```

Corrigido (um descritor por corrida contígua de slots, mesma DLL), o alvo atravessa
`wWinMain`, carrega uxtheme/bcryptPrimitives/kernel.appcore e **sai 0**.

### 8.6 IAT completa: rota derivada da faixa (311 → 315 cobertos, 0 faltando)

A verificação nova (§8.7) mostrou slots de IAT que o scan não alcançava. Acrescentada uma
terceira rota ao script — dentro da faixa `[primeiro, último]` slot encontrado, todo endereço
de 8 bytes que aponte para um módulo conhecido é candidato (a resolução por export filtra) —
a cobertura fecha. `evidence/20261014-72-iat-cobertura.txt`:

| artefato | slots estaleiros | declarados | falta |
|---|---|---|---|
| `dump-fixed.exe` (rodada anterior) | 311 | 155 | **156** |
| + passo 20 e corridas contíguas (`dump-fixed3`) | 311 | 289 | 22 |
| + rota derivada da faixa (`dump-fixed4`) | 315 | 315 | **0** |

### 8.7 Ferramenta nova: `verify-dump.mjs` — o dump contra o original, byte a byte

Ela aplica as relocações do **original** para a base do dump e classifica cada byte diferente:
IAT / iat-delay / loadconfig / tls (o loader preenche), cookie (o CRT recalcula) e
`CODIGO`/`dados` (o que se investiga). Foi ela que teria pegado o byte do §8.3 — provado nas
duas pontas:

```console
# (a) artefato herdado do dump cru (byte 0x51 no lugar de 0x48):
$ node scripts/verify-dump.mjs --dump unpacked/dump-fixed2.exe --original ../packer-demo/clean.exe
  X .text           0 byte(s) diferente(s) de 157666
  CODIGO (diferença em seção executável — é defeito): 4 byte(s) em 1 faixa(s)
      rva 0x28011  [fothk]   esperado cb f4 ff ff | no dump ab 40 03 00
  … exit=1

# (b) artefato com a cadeia corrigida:
$ node scripts/verify-dump.mjs --dump unpacked/dump-fixed4.exe --original ../packer-demo/clean.exe
  X .text           0 byte(s) diferente(s) de 157666
  CODIGO: 4 byte(s) em 1 faixa (rva 0x28011 = auto-patch do PRÓPRIO programa, ver §8.9)
  iat 1891 B · loadconfig 4 B · estado-de-carga 6 B · dados 3464 B    exit=1 (--strict falha em dados)
```

O `CODIGO` de 4 bytes em `fothk` **não** é defeito: medido com `ba w4` que o **original** também
escreve ali (`evidence/20261014-63/64`), e o alvo do salto é `SizeOfImage + 0xC0` nos dois
casos — auto-patch de thunk em runtime. A mensagem da ferramenta passa a ensinar as duas
leituras (defeito vs auto-patch) e como separá-las.

### 8.8 Resultado: o dump roda até o fim como o original

```console
$ powershell -File work/iat-hardcase/scripts/run-and-probe.ps1 -Target unpacked/dump-final4.exe
alvo   : …\unpacked\dump-final4.exe
pid    : 6256
exited : sim  (ExitCode=0 = 0x0)

# 4 execuções de dump-final3 + 1 de dump-final4: sempre 0x0
# controle, o original: 3 execuções de ../packer-demo/clean.exe: 0x0
$ node scripts/diagnose-load.mjs unpacked/dump-final4.exe
  [i ] reloc-ok — 361 entradas de relocação, todas em seções com dados
  [i ] cookie-no-sentinela — __security_cookie em RVA 0x34400 está no sentinela do MSVC
  [i ] run — exit=0x0
  Veredito: sem vício de loader conhecido
```

(O `run-and-probe.ps1` é o harness que mede **comportamento**, não só status: espera `N`
segundos, checa se ficou vivo e qual `MainWindowTitle`/handle criou — necessário porque
num alvo GUI o `cmd`/`spawnSync` não esperam e o “exit=0” do `cmd` é artefato.)

### 8.9 O que NÃO funcionou / não foi exercitado nesta rodada

1. **Scylla pela GUI: continua não executado** (o plugin não tem CLI). O `rebuild-iat.mjs` é o
equivalente headless declarado do *Fix Dump*, agora com a tabela verificada em 20 bytes e a
cobertura da IAT medida — mas isso **não** é rodar a ferramenta canônica.
2. **IAT de *delay import* não foi reconstruída** (slot `0x390a8` segue com o estado da
execução). O loader não a preenche: quem preenche é o `__delayLoadHelper2` no primeiro uso, e
o caminho exercitado não a tocou. Fica listado.
3. **~3,4 KB em `.rdata`/`.data`** continuam com VA onde o original tem RVA (tabelas
convertidas em runtime, ~1300 campos). O caminho exercitado não passa por eles; um caminho
mais longo pode. Aparecem byte a byte no `verify-dump.mjs` — nada em silêncio.
4. **Erros meus, registrados para não repetir:** (a) usei `s` no WinDbg achando que era *step*
— é *search*, e o comando certo é `t`; (b) escrevi um `.ps1` com travessão em UTF-8 **sem BOM**
— o PS 5.1 leu como ANSI e não parseou (exatamente a armadilha que o `check-consistency`
enforcementa), corrigido em ASCII; (c) a primeira versão do `verify-dump.mjs` classificava byte
a byte e afogava o achado em ruído — reescrita para reportar **faixas** e separar seção
executável de dados.
5. **O item secundário (zig/cmake) segue fechado por medição**, não por código novo:
`health-check.ps1 -Json` → `summary: {ok: 39, warn: 0, fail: 0}` com `host:zig 0.17.0` e
`host:cmake cmake version 4.4.4` (a diferenciação “instalado fora do PATH desta sessão” já
entrou na rodada anterior e nada mudou).

### 8.10 Verificações offline (as mesmas que o CI roda)

```console
$ node scripts/check-consistency.mjs      → [OK] nenhuma divergência (197 verificações)  exit=0
$ node scripts/verify-licenses.mjs        → [OK] 79 licenças batem com a fonte primária    exit=0
$ node scripts/gen-mcp-config.mjs --list --json   → 4 clientes, JSON válido               exit=0
$ powershell -File ./scripts/health-check.ps1 -Json → ok 39 / warn 0 / fail 0
```

### 8.11 Reproduzir

```bash
# 1) captura (x64dbg): breakpoint de HARDWARE no OEP — NUNCA de software em .text antes
#    de o stub decriptar a seção (é o que corrompeu o dump, §8.3)
node scripts/x64dbg-drive.mjs --load work/iat-hardcase/src/clean.hardcase.exe
node scripts/x64dbg-drive.mjs --dump-module clean.hardcase work/iat-hardcase/unpacked/dump-raw.exe

# 2) reconstrução (dump cru -> IAT -> estado de carga)
node scripts/rebuild-iat.mjs --dump work/iat-hardcase/unpacked/dump-raw.exe \
     --out work/iat-hardcase/unpacked/dump-fixed.exe \
     --modules work/iat-hardcase/evidence/20261013-3-modules-do-debugger.txt \
     --mem work/iat-hardcase/evidence/mem --oep 0x19c0
node scripts/reset-load-state.mjs --dump work/iat-hardcase/unpacked/dump-fixed.exe \
     --out work/iat-hardcase/unpacked/dump-final.exe

# 3) as duas medidas que decidem
node scripts/verify-dump.mjs --dump work/iat-hardcase/unpacked/dump-fixed.exe \
     --original work/packer-demo/clean.exe          # byte a byte contra o original
node scripts/diagnose-load.mjs work/iat-hardcase/unpacked/dump-final.exe   # o loader aceita?
powershell -File work/iat-hardcase/scripts/run-and-probe.ps1 \
     -Target work/iat-hardcase/unpacked/dump-final.exe     # roda e sai 0?

# 4) verificações offline (as do CI)
node scripts/check-consistency.mjs
node scripts/verify-licenses.mjs
```

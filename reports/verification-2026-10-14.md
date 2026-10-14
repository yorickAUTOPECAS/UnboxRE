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

> O caminho de captura abaixo usa o breakpoint de **software** que corrompeu o dump (§8.3) — ele
> fica aqui como registro histórico da rodada. O caminho atual, com breakpoint de hardware, o log
> de breakpoints e a verificação sem original, está em **§9**.

```bash
# 1) captura (x64dbg): o certo é breakpoint de HARDWARE no OEP — NUNCA de software em .text antes
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
---

## 9. O byte que o breakpoint restaurava errado — causa eliminada e rede de segurança (rodada de 2026-10-14, 2ª parte)

O defeito do §8.3 (breakpoint de **software** em `.text` antes de o stub decriptar → dump com uma
instrução trocada) só foi pego porque existia o original em claro para comparar. Os próximos
alvos não têm original. Esta parte fecha a causa na captura e cria uma rede de segurança que não
depende dele — com as duas provas pedidas: **reprodução do bug** e **captura com hardware já
correta**, cada uma com comando e saída.

### 9.1 O que mudou

| arquivo | mudança |
|---|---|
| `scripts/x64dbg-drive.mjs` | `--hw-break` (**breakpoint de hardware**, DR0-DR3: não escreve na memória), `--hw-type`, `--hw-size`, `--list-breaks`, `--bp-log <arq.jsonl>` (grava cada breakpoint da captura) — o hardware passa a ser o caminho padrão para parar em código que o packer ainda pode reescrever |
| `scripts/x64dbg-drive.mjs` | `--hw-break` **confere** o `ListBreakpoints` e falha (exit 1) quando o endereço não foi armado — o x64dbg aceita o 5º em silêncio (medido) |
| `scripts/verify-dump.mjs` | **MODO FRACO** sem `--original` (`--packed` + `--bp-log`): resíduo de `0xCC`, byte parado no tempo nos endereços do log, faixa ainda cifrada — rotulado na própria saída como substituto |
| `docs/06-workflows.md` | Cenário 1: passo 4 passa a ser breakpoint de hardware, quadro de quando usar cada tipo com o limite medido, receita de sessão limpa, passo 12 (verificação sem original) e a armadilha medida reescrita como **tratada por padrão** |
| `docs/02-catalogo-ferramentas.md`, `README.md`, `scripts/README.md` | catálogo e tabelas de script descrevem as duas ferramentas novas de captura/verificação |

### 9.2 Prova A — o bug, reproduzido de propósito

```console
$ cd work/iat-hardcase && bash scripts/prova-a-swbp.sh
# breakpoint de SOFTWARE em base+0x1F98, com a seção .text ainda CIFRADA, run, DumpModule
RVA 0x1f98  51 fd 93 0e 9d b5 73 1d   ← empacotado (o que estava na memória antes do stub)
RVA 0x1f98  51 89 5c 24 18 55 48 8b   ← dump capturado agora (BP de SOFTWARE)
RVA 0x1f98  48 89 5c 24 18 55 48 8b   ← original em claro (referência)
```

`0x51 = 0x48 ^ 0x19`, o byte do arquivo empacotado: o debugger devolveu o valor **pré-decriptação**.
Evidência: `work/iat-hardcase/evidence/20261014-82-prova-a-swbp.txt`.

### 9.3 Prova B — a mesma parada com breakpoint de hardware

Sessão nova, banco do módulo apagado (`db/clean.hardcase.exe.dd64`), log
`evidence/20261014-84-prova-b-hwbp.txt`:

```console
$ bash scripts/prova-b-hwbp.sh
─ SetHardwareBreakpoint {"address":"0x7ff703e71f98","type":"x","size":1}
  Hardware breakpoint set.
  [Hardware] 0x7FF703E71F98 clean.hardcase.exe! (enabled)
…
RVA 0x1f98  48 89 5c 24 18 55 48 8b   <- dump capturado agora (BP de HARDWARE)
RVA 0x1f98  51 89 5c 24 18 55 48 8b   <- dump da Prova A (BP de SOFTWARE)
RVA 0x1f98  48 89 5c 24 18 55 48 8b   <- original em claro (referência)
```

E a cadeia a partir **dessa** captura, sem patch manual nenhum (`evidence/20261014-85`, `-86`, `-87`):

```console
$ node scripts/x64dbg-drive.mjs --modules > evidence/20261014-86-modules-bp.txt   # 18 módulos
$ node scripts/rebuild-iat.mjs --dump unpacked/dump-hwbp.exe --out unpacked/dump-hwbp-fixed2.exe \
       --modules evidence/20261014-86-modules-bp.txt --mem evidence/mem --oep 0x19c0
  IAT encontrada: 315 slot(s) resolvido(s) — 48 por thunk direto, 288 por varredura
  70 DLL(s) reconstruída(s)  ·  [!!] 2 slot(s) sem resolução  ·  exit=0
$ node scripts/reset-load-state.mjs --dump unpacked/dump-hwbp-fixed2.exe \
       --out unpacked/dump-hwbp-final2.exe
  cookie: antes = 0x00006a5347c34196 (estado de EXECUÇÃO) → depois = 0x00002b992ddfa232 (sentinela MSVC)
$ node scripts/verify-dump.mjs --dump unpacked/dump-hwbp-fixed2.exe --original ../packer-demo/clean.exe
  X .text           0 byte(s) diferente(s) de 157666
  CODIGO: 4 byte(s) em 1 faixa (rva 0x28011 [fothk] — auto-patch do próprio programa, §8.9)
$ powershell -File scripts/run-and-probe.ps1 -Target unpacked/dump-hwbp-final2.exe
  exited : sim  (ExitCode=0 = 0x0)        ← 4/4 execuções
```

Detalhe que custou uma tentativa errada e virou passo do Cenário 1: a lista de módulos tem de ser
tomada **no ponto de parada**. No EP (antes de o stub carregar as DLLs do alvo) ela tinha **4**
módulos e o rebuild resolvia 126 slots em 53 blocos; no ponto de parada são **18** módulos e 315
slots em 70 blocos (`evidence/20261014-84-modules.txt` vs `-86-modules-bp.txt`).
### 9.4 Prova C — sem original, o modo fraco pega o mesmo byte

`evidence/20261014-89-prova-c.txt`:

```console
# A) captura com BP de SOFTWARE, modo FORTE (--original):
  CODIGO: 5 byte(s) em 2 faixa(s)
      rva 0x1f98  1B  [.text]   esperado 48 89 5c 24 | no dump 51 89 5c 24      exit=1

# B) o MESMO arquivo, SEM original (--packed + --bp-log da captura):
  endereços de breakpoint da captura: 2 (log: 20261014-82-bp-log-soft.jsonl)
      0x7ff703e71f98  [sw] rva 0x1f98 byte 0x51 · empacotado 0x51 · seção reescrita 99.6%
          o byte é o do arquivo EMPACOTADO e a seção foi reescrita: o debugger devolveu o
          valor pré-escrita (defeito do iat-hardcase)
  Veredito: 2 achado(s) de marca conhecida de defeito (modo fraco, sem original)      exit=1

# C) a MESMA captura com hardware, sem original: nenhuma das 3 marcas · exit=0
```

E a checagem de `0xCC` **tem dentes** (senão seria teatro): forçando `0xCC` em `0x1F98` num dump
bom (`unpacked/dump-hwbp-int3.exe`),

```console
  Veredito: 1 achado(s) de marca conhecida de defeito (modo fraco, sem original):
      [int3-em-breakpoint] rva 0x1f98  int3 no endereço de um breakpoint do log da captura   exit=1

# o MESMO arquivo, sem --bp-log: o 0xCC cai na lista de candidatos (293 ocorrências — o padding
# do MSVC está entre elas) e o veredito sai 0. Sem o log da captura, a rede quase não serve.
```

**O que o modo fraco NÃO vê** (declarado na saída da ferramenta e no cabeçalho): byte trocado por
valor plausível em endereço **sem** breakpoint, seção remontada errada, patch manual. Ele não
prova que o dump está limpo — é o que existe quando não há original em claro.

### 9.5 Limites medidos (em vez de supostos)

```console
$ node scripts/x64dbg-drive.mjs --hw-break 0x7ff703e72300     # com 4 slots já ocupados
─ SetHardwareBreakpoint {"address":"0x7FF703E72300","type":"x","size":1}
  Hardware breakpoint set.                                     ← disse que sim
─ ListBreakpoints {}
  [Hardware] 0x7FF703E71F98 … 0x7FF703E72000 … 0x7FF703E72100 … 0x7FF703E72200 …
  [!!] breakpoint de hardware NÃO foi armado em 0x7ff703e72300: a lista não mostra esse
       endereço (DR0-DR3 = 4 por thread, já ocupados) — o x64dbg respondeu "set" mesmo assim
  exit do driver = 1   ·   --bp-log: {"kind":"hw","address":"0x7ff703e72300","armed":false}
```

* **4** breakpoints de hardware por thread (DR0-DR3), medido; para mais pontos:
  `SetMemoryBreakpoint` (guard page) ou software **depois** que a seção está em claro
  (`evidence/20261014-88-limite-dr.txt`, `…-90-hw-break-armed.txt`).
* **A sessão não é limpa por reiniciar o debugger**: o x64dbg persiste breakpoints por módulo em
  `x64dbg/release/x64/db/<módulo>.dd64` e eles voltam armados na carga seguinte — medido com os 4
  de hardware ainda na lista depois de reiniciar. Só com o banco apagado e o debugger reaberto a
  lista fica `No breakpoints set.` (é o passo 0 do Cenário 1).
* **O x64dbg também para em TLS callback de DLL de sistema**: na captura do caso a sequência de
  `run` precisou de 3 paradas até cair no breakpoint de hardware (`evidence/20261014-84`, §6).
  Script que conta com 1 `run` só, falha.

### 9.6 Checagens offline (as mesmas do CI), depois de tudo

```console
$ node scripts/check-consistency.mjs      → [OK] nenhuma divergência (197 verificações)   exit=0
$ node scripts/verify-licenses.mjs        → [OK] 79 licenças batem com a fonte primária   exit=0
$ node scripts/gen-mcp-config.mjs --list --json  → 4 clientes, JSON válido                exit=0
```
### 9.7 Reproduzir (o caminho novo, do zero)

```bash
# 0) sessão limpa: sem isso um breakpoint de rodada anterior contamina a captura
powershell -File ./scripts/start-x64dbg.ps1 -Stop
rm -f x64dbg/release/x64/db/clean.hardcase.exe.dd64 x64dbg/release/x64/db/clean.hardcase.exe.dd64.cmdline
powershell -File ./scripts/start-x64dbg.ps1
node scripts/x64dbg-drive.mjs --list-breaks            # tem de dizer "No breakpoints set."

# 1) A PROVA DO BUG (breakpoint de software antes de o stub decriptar) — para ver o defeito acontecer
cd work/iat-hardcase && bash scripts/prova-a-swbp.sh   # dump-swbp.exe com 0x51 na rva 0x1F98

# 2) A CAPTURA CERTA (hardware) e a cadeia inteira, sem patch manual
bash scripts/prova-b-hwbp.sh                           # dump-hwbp.exe com 0x48 na rva 0x1F98
node scripts/rebuild-iat.mjs --dump unpacked/dump-hwbp.exe --out unpacked/dump-hwbp-fixed2.exe \
     --modules evidence/20261014-86-modules-bp.txt --mem evidence/mem --oep 0x19c0
node scripts/reset-load-state.mjs --dump unpacked/dump-hwbp-fixed2.exe --out unpacked/dump-hwbp-final2.exe
powershell -File scripts/run-and-probe.ps1 -Target unpacked/dump-hwbp-final2.exe   # exit 0

# 3) AS DUAS VERIFICAÇÕES: com original (forte) e sem original (fraca, rotulada como tal)
node scripts/verify-dump.mjs --dump unpacked/dump-hwbp-fixed2.exe --original ../packer-demo/clean.exe
node scripts/verify-dump.mjs --dump unpacked/dump-hwbp-fixed2.exe \
     --packed src/clean.hardcase.exe --bp-log evidence/20261014-84-bp-log-hw.jsonl

# 4) o modo fraco sobre o artefato corrompido (Prova A/C) e o limite do DR (Prova D)
bash scripts/prova-c.sh ; bash scripts/prova-d-hwbreak-armed.sh
```

### 9.8 O que continua aberto (honesto)

* **Scylla pela GUI** segue não executado (o plugin não tem CLI) — inalterado em relação a §8.9.
* O modo fraco **não** substitui a comparação com original: alvo sem original em claro tem
  cobertura parcial declarada, não garantia.
* Os 6 alvos reais da pasta `Alvos` **não** foram tocados nesta rodada, por escopo: a primeira
  tarefa do round seguinte é listar o conteúdo da pasta (nome, dificuldade declarada) antes de
  escolher qual atacar.
### 9.9 Nota: o CI dos dois commits ficou vermelho por indisponibilidade de um site de terceiro

Os dois commits desta rodada foram empurrados com ~1 minuto de diferença (`dcfdebe`, `d270b5c`) e
**os dois** ficaram com o job `licenses` vermelho. Investigado, não é defeito do código nem do
conteúdo do commit — é indisponibilidade de **um** host de terceiro. Log do job (run
[38597582145](https://github.com/yorickAUTOPECAS/UnboxRE/actions/runs/38597582145)):

```console
     API Monitor     declara LicenseRef-Freeware-Rohitab raw:n/a        api:n/a
       · não consegui ler o LICENSE: HTTP 503
  [FAIL] API Monitor: falha de rede lendo http://www.rohitab.com/apimonitor
##[error]Process completed with exit code 1.

# no outro run (38597678303), o mesmo host e o mesmo veredito:
       · não consegui ler o LICENSE: fetch failed
  [FAIL] API Monitor: falha de rede lendo http://www.rohitab.com/apimonitor
```

Fatos medidos, um por um:

| medição | comando | resultado |
|---|---|---|
| o host voltou? | `curl -s -o /dev/null -w "%{http_code}" -L http://www.rohitab.com/apimonitor` ×3 | `200`, `200`, `200` |
| o script mudou nesta rodada? | `git diff f4a68c0..d270b5c -- scripts/verify-licenses.mjs` | sem alteração |
| o mesmo código, localmente | `node scripts/verify-licenses.mjs` | `[OK] 79 licenças…`, exit `0` |
| re-execução dos jobs | `gh run rerun 38597678303 --failed` · `gh run rerun 38597582145 --failed` | os dois runs passaram (ver abaixo) |

Os **4** jobs do commit mais recente em `main` (`d270b5c`), todos verdes —
[run 38597678303](https://github.com/yorickAUTOPECAS/UnboxRE/actions/runs/38597678303):

```console
$ gh run view 38597678303 --json jobs
  success  Licenças contra a fonte primária
  success  Documentação e estrutura
  success  Scan de segredos e binários
  success  Ponte MCP do REA sobe e responde
```

**O terceiro commit também ficou vermelho no mesmo ponto** — o único job que falha é o que faz
HTTP a hosts de terceiros, e sempre na mesma linha. Run
[38600190104](https://github.com/yorickAUTOPECAS/UnboxRE/actions/runs/38600190104) (`3022d93`):

```console
  success Scan de segredos e binários
  success Documentação e estrutura
  failure Licenças contra a fonte primária
  success Ponte MCP do REA sobe e responde

  !! API Monitor     declara LicenseRef-Freeware-Rohitab raw:n/a        api:n/a
       · não consegui ler o LICENSE: HTTP 503
  [FAIL] API Monitor: falha de rede lendo http://www.rohitab.com/apimonitor
##[error]Process completed with exit code 1.
```

**O host é que oscila, medido dos dois lados** (evidência bruta em `work/.ci/host-flakiness.txt`):

```console
# da minha máquina, 10 probes seguidos em http://www.rohitab.com/apimonitor:
  probe  1..10 -> HTTP 200   (todos)
# minutos antes, na mesma máquina, 5 probes:
  probe 1,2,3 -> HTTP 000   probe 4 -> HTTP 200   probe 5 -> HTTP 000
# e do runner do GitHub, 3 execuções do job: HTTP 503 · "fetch failed" · HTTP 503
```

Ou seja: a fonte primária dessa **uma** declaração (API Monitor, freeware da Rohitab) responde de
forma intermitente — 200 para a minha rede, 503/erro de conexão para o runner e, às vezes, para
mim também (`HTTP 000` = sem resposta). Repetindo o job do **mesmo SHA**, ele passa: o gate não é
determinístico por causa de um site de terceiro, não por causa do código.

**Leitura:** o `verify-licenses.mjs` **falha de propósito** quando não consegue ler a fonte
primária (é a regra nº 5 do projeto: toda afirmação de licença vem da fonte primária) — o efeito
colateral é que a indisponibilidade de um site de terceiro pinta o CI de vermelho mesmo com o
código intacto. A hipótese de *rate limit* de API entre os dois pushes não se sustenta: a falha
foi sempre na **mesma** linha, do único job que faz requisição HTTP a hosts de terceiros.

**Fechamento:** o commit mais recente em `main` (`3022d93`) está **verde nos 4 jobs** depois de
re-executar só o job de licenças —
[run 38600190104](https://github.com/yorickAUTOPECAS/UnboxRE/actions/runs/38600190104):
`success Licenças contra a fonte primária · success Documentação e estrutura · success Scan de
segredos e binários · success Ponte MCP do REA sobe e responde`.

Depois desta nota, o commit final da rodada (`fab862f`, que só acrescenta o texto acima) passou
na **primeira** execução, sem re-run —
[run 38602339115](https://github.com/yorickAUTOPECAS/UnboxRE/actions/runs/38602339115):
`success Licenças contra a fonte primária · success Documentação e estrutura · success Scan de
segredos e binários · success Ponte MCP do REA sobe e responde`.

> **Limitação declarada (não resolvida nesta rodada):** o job de licenças depende de um host
> instável e por isso pode ficar vermelho sem nenhum defeito no repositório. Não mascarei isso
> mexendo no gate: as afirmações de licença continuam vindo da fonte primária e o script continua
> falhando quando não consegue lê-la. A decisão de tornar o gate resiliente a 5xx transitório
> (retry com backoff, sem afrouxar a verificação) é do dono do projeto — está registrada aqui
> como pendência com a medição que a justifica.

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
   Quem falta ser tentado é o leitor **dentro** do debugger: janela *Log* do x64dbg e
   WinDbg (instalado). Consequência honesta para o caso duro: a pergunta “qual checagem do
   `ntdll` reprova o `dump-fixed.exe`” **continua em aberto**.
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

# scripts/ — automação do UnboxRE

Todos os scripts são **idempotentes** e **dry-run por padrão**: rodar duas vezes
não quebra nada, e nada é instalado/compilado/copiado sem uma flag explícita
(`-Apply` / `--apply`).

> Caminhos abaixo assumem a raiz do toolkit. Use PowerShell no Windows. O escopo
> atual é **Windows 10/11**: o caminho crítico é validado aqui. O ramo `bash` existe
> para Git Bash e como roadmap — Linux/WSL **não** é suportado/testado nesta rodada.

---

## Mapa

| Script | Ambiente | O que faz | Escreve? |
|---|---|---|---|
| `fetch-tools.ps1` | Windows (PS 5.1/7) | baixa o núcleo de terceiros do upstream (Ghidra, x64dbg, REA, MCP), com checksum | com `-Apply` |
| `fetch-tools.sh` | Git Bash / WSL | o mesmo (delega ao `.ps1`; no Linux faz ghidra+rea) | com `--apply` |
| `health-check.ps1` | Windows (PS 5.1/7) | diagnóstico completo; `-Fix-Paths` cria diretórios e repara `GHIDRA_INSTALL_DIR`/`JAVA_HOME` | só com `-Fix-Paths` |
| `health-check.sh` | Git Bash / WSL | versão POSIX do diagnóstico | não |
| `bootstrap-windows.ps1` | Windows | instala por perfil (winget/choco/pip/npm); o perfil `core` roda o `fetch` antes | com `-Apply` |
| `bootstrap-wsl.sh` | WSL (Ubuntu) | instala o lado Linux (gdb, angr, pwndbg, gef, unblob…) — **fora de escopo por ora** (roadmap) | com `--apply` (pede confirmação; `--yes` pula) |
| `re-build.ps1` | Windows | compila x64dbg-MCP (Zig) e REA (npm) da FONTE — opcional | com `-Apply` |
| `setup-ghidra-extensions.ps1` | Windows | instala extensões `.zip` no Ghidra | com `-Apply` |
| `new-case.ps1` | Windows | cria `work/<slug>/` com intake e hash | sim |
| `scan-secrets.ps1` | Windows (pwsh) | procura segredos e arquivos indevidos | não |
| `gen-mcp-config.mjs` | Node | gera/valida as configs MCP por cliente | com `--apply` (grava em `config/mcp/generated/`) |
| `identify-protections.mjs` | Node | triagem de packer/protetor por assinatura (UPX, VMProtect, Themida…) | não |
| `triage-static.mjs` | Node | triagem **sem debugger**: cabeçalho/seções (permissões, entropia), **TLS callbacks** (código que o loader roda ANTES do entrypoint), imports por DLL e strings **só de seções não executáveis** com a RVA de cada uma — e, com `--refs`, onde cada uma é usada no código (uma passada no código, indexada; varrer por string não escala) | não |
| `disasm-range.py` | Python + capstone | desmonta um intervalo de RVA (ou uma seção inteira com `--section .text`) e anota strings RIP-relativas. Dependência declarada: `capstone` — que entra pelo perfil `static` e é sondado por **módulo Python**, porque biblioteca não tem comando no PATH | não |
| `diagnose-load.mjs` | Node | "por que este .exe sai com 0xC000007B?": vícios de loader (seções esvaziadas, dir em seção sem dados, ASLR sem reloc, `__security_cookie` em estado de execução) + o status real da execução | não |
| `make-packed-sample.mjs` | Node | fabrica um alvo empacotado (stub em `lib/pkr-stub.rs`) a partir de um PE que roda: XOR do código, IAT por DLL, EP → stub → OEP | sim (o `.exe` gerado) |
| `rebuild-iat.mjs` | Node | equivalente headless do *Fix Dump* do Scylla: acha a IAT num dump de memória, resolve cada slot (nome/ordinal) e escreve uma seção `.idata2` nova | com `--out` |
| `reset-load-state.mjs` | Node | dump de memória recusado pelo loader (`0xC000007B`): repõe o `__security_cookie` no sentinela do MSVC que o `LdrInitSecurityCookie` exige, devolvendo a imagem ao estado de carga | com `--out` |
| `verify-dump.mjs` | Node | confere o dump reconstruído contra o **original em claro**: aplica as relocações do original para a base do dump e classifica cada byte diferente (IAT/LOAD_CONFIG/TLS = o loader preenche; cookie = o CRT recalcula; `CODIGO`/`dados` = o que investigar). Pega byte escrito por engano no dump (ex.: breakpoint de software antes da decriptação). Sem `--original`, entra em **MODO FRACO** (`--packed`/`--bp-log`): resíduo de `0xCC`, byte parado no tempo e faixa ainda cifrada — substituto declarado, **não** prova de dump limpo | não |
| `x64dbg-drive.mjs` | Node | dirige o x64dbg pelo MCP (load, `--break`/`--hw-break`, `ReadMemory`, `GetMemoryMap`, `DumpModule`…) — a ponte scriptável entre o debugger e o caso em análise. `--hw-break` = breakpoint de hardware (DR0-DR3, não escreve na memória) e **falha se o endereço não foi armado** (o x64dbg descarta o 5º em silêncio); `--bp-log` grava os breakpoints para o `verify-dump` sem original | conforme o comando |
| `load-snaps.ps1` | Windows (elevado) | liga/desliga *loader snaps* (`FLG_SHOW_LDR_SNAPS`) para uma imagem — o efeito de `gflags /i app.exe +sls`, sem o gflags.exe | com `-Apply`, em shell elevado |
| `capture-debugprint.ps1` | Windows | listener do canal `DBWIN_BUFFER` (OutputDebugString/DbgPrint) para alvos **fora** do debugger — validado por auto-teste; medido que ele **não** recebe *loader snaps* neste host (para snaps, leia a janela Log do x64dbg/WinDbg — ver [docs/tools/gflags.md](../docs/tools/gflags.md)) | com `-OutFile` |
| `check-consistency.mjs` | Node | regressão offline: doc ↔ código ↔ licenças divergindo | não |
| `verify-licenses.mjs` | Node (rede) | confere cada licença contra a fonte primária; **retry limitado** (até 4 tentativas, 1 s → 2 s → 4 s, timeout de 20 s) só em erro de rede/status transitório — um `LICENSE` que responde e não confere reprova na 1ª resposta, e as tentativas saem na própria saída | não |
| `smoke-mcp.mjs` | Node | handshake MCP real (initialize + tools/list) contra o REA | não |
| `start-x64dbg.ps1` | Windows | sobe o x64dbg minimizado para o plugin MCP ficar vivo; espera a porta e, com `-Check`, roda a chamada MCP real | não (com `-Stop` encerra o que subiu) |
| `mcp-x64dbg-smoke.mjs` | Node | prova que o MCP do x64dbg responde ao vivo (initialize → tools/list → uma tool real) | não |
| `lib/common.ps1` | — | helpers compartilhados (dot-source) | — |

---

## Sequência recomendada (primeira vez)

```powershell
# 1. Veja o que falta
.\scripts\health-check.ps1

# 2. Busque o núcleo de terceiros (clone limpo não traz ghidra/, x64dbg/, rea-main/)
.\scripts\fetch-tools.ps1                                # mostra o plano
.\scripts\fetch-tools.ps1 -Apply                         # baixa do upstream

# 3. Instale o toolchain e as ferramentas que você quer
.\scripts\bootstrap-windows.ps1 -Profile core            # mostra o plano
.\scripts\bootstrap-windows.ps1 -Profile core -Apply     # instala (já inclui o fetch)

# 4. (Opcional) compile os componentes da FONTE — o fetch já traz releases prontos
.\scripts\re-build.ps1 -Apply

# 5. (Opcional) provisione o lado Linux — FORA DE ESCOPO POR ORA (roadmap;
#    o caminho suportado e testado hoje é só o Windows)
wsl -d Ubuntu -- bash -lc "cd $(wslpath -u 'C:\Users\Admin\Desktop\UnboxRE') && bash scripts/bootstrap-wsl.sh --apply --yes"

# 6. (Opcional) ponha o x64dbg no ar e prove o MCP ao vivo
.\scripts\start-x64dbg.ps1 -Check

# 6. Gere as configs de MCP para o seu cliente
node .\scripts\gen-mcp-config.mjs --client claude-desktop --apply

# 7. Confirme tudo
.\scripts\health-check.ps1
```

---

## Perfis do bootstrap

`-Profile` aceita: `fetch`, `core`, `static`, `dynamic`, `mobile`, `firmware`,
`net`, `plugins`, `all`, além dos aliases usados na documentação — `formats`
(= mobile+firmware), `network` (= net), `wsl`, `full` (= all). Cada ferramenta
carrega o motivo de existir e a licença; o bootstrap nunca instala nada fora do
catálogo declarado.

## Convenções

- **Dry-run sempre primeiro.** Sem `-Apply`, o script mostra o plano exato.
- **Nunca sudo.** Se um instalador exigir elevação, ele mesmo pede — o script não
  contorna.
- **Script Python que imprime símbolo** (`─`, `·`): o `stdout` do Python no Windows
  herda a code page (**cp1252**) e o `print` do desenho derruba o script com
  `UnicodeEncodeError` **no meio da saída** — medido no round 8.1, quando ela era
  redirecionada para `evidence/`. Ajuste o encoding antes de imprimir (como em
  `disasm-range.py`) ou fique em ASCII.
- **Exit codes:** `0` sucesso · `1` falha de verificação · `2` erro de execução.
- **Saída JSON** (`health-check.ps1 -Json`, `scan-secrets.ps1 -Json`) para CI.

## CI

`.github/workflows/ci.yml` valida, a cada push:

- **validate** — arquivos obrigatórios, JSON dos templates MCP, `shellcheck`,
  sintaxe de todo `.ps1`/`.sh`/`.mjs`, `gen-mcp-config --list --json` e a
  verificação de consistência offline;
- **licenses** — cada licença declarada conferida contra o upstream (rede);
- **mcp-smoke** — a ponte MCP do REA faz um handshake real;
- **secrets** — a barreira que impede publicar um token ou um binário de alvo.

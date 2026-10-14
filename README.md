# UnboxRE — Toolkit de Engenharia Reversa operado por IA

Monorepo de ferramentas, documentação e automação para **engenharia reversa de software**
(análise estática, dinâmica, desobfuscação, formatos de binário, rede e fuzzing),
com foco em **operação por LLM/agentes** através de CLI e MCP.

> Licenças e compatibilidade: [docs/03-licencas.md](docs/03-licencas.md). Atribuição de
> cada projeto de terceiros que o toolkit orquestra: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

## 1. Mapa rápido do stack

**Escopo atual: Windows 10/11.** O toolkit é validado num host Windows, e é onde o
caminho crítico (PE/PE+, .NET/IL, kernel, GUI Ghidra/x64dbg, servidores MCP) foi
testado de ponta a ponta. Linux/WSL e macOS **não estão em escopo por ora** — seguem
no roadmap. Os ganchos que existem para eles (`bootstrap-wsl.sh`, o ramo Linux de
`fetch-tools.sh`) são cortesia, não promessa de suporte.

| Terreno | O que cobre | Estado |
|---|---|---|
| **Host Windows** (`C:\Users\Admin\Desktop\UnboxRE`) | PE/PE+, .NET/IL, drivers, kernel Windows, processos vivos, GUI (Ghidra/x64dbg), MCP servers | **suportado e testado** — o caminho crítico |
| **WSL2 Ubuntu / Linux / macOS** | ELF, Android/APK, firmware/IoT, fuzzing (AFL++), angr/Qiling, símbolos DWARF | fora de escopo por ora (roadmap) |

```
                    ┌──────────────────── LLM / Agente ────────────────────┐
                    │  Claude Code · Codex · Cursor · OpenCode · Gemini …  │
                    └───────┬──────────────┬───────────────┬───────────────┘
                            │ MCP (stdio)  │ MCP (HTTP)    │ MCP (stdio)
                    ┌───────▼───────┐ ┌────▼──────────┐ ┌──▼────────────┐
                    │  REA (bridge) │ │ x64dbg-MCP    │ │ r2 / IDA /    │
                    │  ghidra/ida/  │ │ (in-process   │ │ GhidraMCP …   │
                    │  jeb/hopper   │ │  no x64dbg)   │ │               │
                    └───────┬───────┘ └────┬──────────┘ └──┬────────────┘
                            │              │               │
              ┌─────────────▼──┐   ┌───────▼───────┐  ┌────▼─────────────┐
              │ Ghidra 12.1.4  │   │ x64dbg 2026.05│  │ radare2 / IDA    │
              │ + JDK 27       │   │ + plugins     │  │ Free / JEB       │
              │ (estático)     │   │ (dinâmico)    │  │ (estático)       │
              └────────────────┘   └───────────────┘  └──────────────────┘
                            │              │
              ┌─────────────▼──────────────▼──────────────────────────────┐
              │  Frida · DynamoRIO · TinyInst · Qiling · WinDbg/TTD       │
              │  Unicorn · Speakeasy · VM/Windows Sandbox (isolamento)    │
              └───────────────────────────────────────────────────────────┘
              ┌───────────────────────────────────────────────────────────┐
              │  mitmproxy · Wireshark/tshark · Kaitai · boofuzz · AFL++   │
              └───────────────────────────────────────────────────────────┘
```

---

## 2. Estado atual (auditado em 2026-10-13)

Os quatro NÚCLEO de terceiros (`ghidra/`, `x64dbg/`, `rea-main/`, o plugin MCP)
**não são versionados** por licença — um clone limpo não os tem, e `fetch-tools`
os baixa do upstream. Nesta máquina, após o fetch:

| Ferramenta | Versão | Estado | Observação |
|---|---|---|---|
| Ghidra | 12.1.4 PUBLIC (build 20260921) | ✅ funcional | `analyzeHeadless` analisa um PE real de ponta a ponta ([evidência](reports/evidence-packer-upx.md)) |
| JDK | 21 LTS no `PATH` + 27 em `ghidra/jdk-27` | ✅ | Ghidra 12.1.4 exige `>=21`; o pin do toolkit é o **21 LTS** |
| x64dbg | snapshot 2026-05-27 | ✅ funcional | `release/{x32,x64}/plugins/` criado pelo fetch |
| REA (`rea-agents`) | 6.4.0 | ✅ funcional | instalado via tarball npm; `rea doctor` reconhece o Ghidra |
| x64dbg-MCP Server | 1.6 (release pré-compilado) | ✅ instalado | `.dp64`/`.dp32` copiados para o x64dbg; **Zig não é mais necessário** (só ao compilar da fonte) |
| Toolchain auxiliar | zig/7z/cmake… | ⚠️ opcional | o fetch usa o release pré-compilado do MCP; Zig só para build da fonte |

Detalhes, causa-raiz e plano de correção: **[docs/00-diagnostico.md](docs/00-diagnostico.md)**.

---

## 3. Comece aqui (clone limpo → análise)

Num clone novo, os quatro diretórios do núcleo ainda não existem. O primeiro passo
é buscá-los do upstream (Ghidra, x64dbg, REA, x64dbg-MCP — nunca vendorizados):

```powershell
# 0) Verificar o estado real do ambiente (somente leitura, não instala nada)
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\health-check.ps1

# 1) Buscar o núcleo de terceiros do upstream (dry-run primeiro!)
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\fetch-tools.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\fetch-tools.ps1 -Apply

# 2) Complementar com a toolchain (dry-run primeiro!)
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1 -Profile core -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1 -Profile core

# 3) Gerar as configurações MCP para os clientes de IA
node .\scripts\gen-mcp-config.mjs --client vscode --check
```

Em Git Bash, os equivalentes são `bash scripts/health-check.sh` e
`bash scripts/fetch-tools.sh`. O perfil `core` do bootstrap também roda o `fetch`
como primeiro passo, então `-Profile core` já cobre os passos 1 e 2.

| Perfil do bootstrap | Conteúdo | Tempo aproximado |
|---|---|---|
| `fetch` | Baixa o NÚCLEO de terceiros do upstream (Ghidra, x64dbg, REA, x64dbg-MCP) | ~5 min (com cache) |
| `core` | `fetch` + toolchain de build (Zig, Node, JDK, cmake, Rust, Python) | ~10 min |
| `static` | + radare2/rizin, LIEF, capstone, YARA, DIE, ghidriff, ImHex | ~15 min |
| `dynamic` | + Frida, DynamoRIO, WinDbg/TTD, ScyllaHide, PE-sieve, Moneta, Sysinternals | ~15 min |
| `mobile`, `firmware` | Android (jadx/apktool) e firmware (binwalk/unblob) — alias histórico: `formats` | ~20 min |
| `net` | Wireshark/tshark, mitmproxy, Fluxzy — alias histórico: `network` | ~10 min |
| `plugins` | Instala os plugins compilados no x64dbg (delega a `re-build.ps1`) | ~5 min |
| `wsl` | Provisiona o laboratório Linux (delega a `bootstrap-wsl.sh`; rode dentro do WSL) — **fora de escopo por ora** | ~25 min |
| `all` | Tudo acima, em ordem — alias histórico: `full` | ~1 h |

---

## 4. Índice da documentação

| Documento | Para que serve |
|---|---|
| [00-diagnostico.md](docs/00-diagnostico.md) | Auditoria: o que funciona, o que falta, causa-raiz, risco |
| [01-arquitetura.md](docs/01-arquitetura.md) | Estrutura de diretórios, convenções de nome, fluxo de trabalho, onde cada artefato mora |
| [02-catalogo-ferramentas.md](docs/02-catalogo-ferramentas.md) | **Catálogo exaustivo** por domínio (a–g), com "quando usar", "como usar", integração e licença |
| [03-licencas.md](docs/03-licencas.md) | Matriz de licenças, compatibilidade MIT, o que pode/não pode ir para o GitHub |
| [04-instalacao.md](docs/04-instalacao.md) | Instalação passo a passo, por perfil, com verificação |
| [05-mcp.md](docs/05-mcp.md) | Todos os servidores MCP, variáveis, tokens, ordem de subida, troubleshooting |
| [06-workflows.md](docs/06-workflows.md) | **Guias passo-a-passo** para os 12 cenários mais comuns |
| [07-operacao-por-ia.md](docs/07-operacao-por-ia.md) | Contrato de operação para LLM: o que pode fazer sozinha, quando parar, como reportar evidência |
| [08-higiene-e-seguranca.md](docs/08-higiene-e-seguranca.md) | Isolamento de amostras, snapshots de VM, rede, cadeia de custódia |
| [tools/ghidra.md](docs/tools/ghidra.md) | Ficha da ferramenta: Ghidra |
| [tools/x64dbg.md](docs/tools/x64dbg.md) | Ficha da ferramenta: x64dbg |
| [tools/rea.md](docs/tools/rea.md) | Ficha da ferramenta: REA |
| [tools/x64dbg-mcp.md](docs/tools/x64dbg-mcp.md) | Ficha da ferramenta: x64dbg-MCP Server |

Automação:

| Script | Função |
|---|---|
| [scripts/fetch-tools.ps1](scripts/fetch-tools.ps1) | Baixa e instala o NÚCLEO de terceiros do upstream (Ghidra, x64dbg, REA, x64dbg-MCP) — o passo que faz o clone limpo funcionar |
| [scripts/fetch-tools.sh](scripts/fetch-tools.sh) | O mesmo em Git Bash (delega ao `.ps1`) / WSL (ghidra+rea) |
| [scripts/health-check.ps1](scripts/health-check.ps1) | Diagnóstico do ambiente (PS 5.1), com `-Json` para consumo por IA |
| [scripts/health-check.sh](scripts/health-check.sh) | Mesmo diagnóstico em Git Bash |
| [scripts/bootstrap-windows.ps1](scripts/bootstrap-windows.ps1) | Instalação por perfil, idempotente, com `-DryRun` |
| [scripts/bootstrap-wsl.sh](scripts/bootstrap-wsl.sh) | Provisionamento da toolchain Linux dentro do WSL |
| [scripts/gen-mcp-config.mjs](scripts/gen-mcp-config.mjs) | Gera/valida os blocos `mcpServers` para cada cliente de IA |
| [scripts/identify-protections.mjs](scripts/identify-protections.mjs) | Triagem embutida de packer/protetor (UPX, VMProtect, Themida, ASPack…), sem dependência externa |
| [scripts/diagnose-load.mjs](scripts/diagnose-load.mjs) | "Por que este .exe sai com 0xC000007B?": vícios de loader (seções esvaziadas, diretório de dados em seção sem bytes, ASLR sem reloc, `__security_cookie` em estado de execução) + o status real da execução |
| [scripts/x64dbg-drive.mjs](scripts/x64dbg-drive.mjs) | Dirige o x64dbg pela ponte MCP, sem clicar na GUI: load, breakpoint, `ReadMemory`, `GetMemoryMap`, `DumpModule`. `--hw-break` usa **breakpoint de hardware** (não escreve na memória — o padrão para código que o packer ainda pode reescrever) e **confere se foi armado**; `--bp-log` grava os endereços para o `verify-dump` |
| [scripts/rebuild-iat.mjs](scripts/rebuild-iat.mjs) | Equivalente headless do *Fix Dump* do Scylla: acha a IAT num dump de memória, resolve cada slot (nome/ordinal) e escreve a tabela nova |
| [scripts/reset-load-state.mjs](scripts/reset-load-state.mjs) | Tira um dump de memória do estado de execução: repõe o `__security_cookie` no sentinela que o loader exige, senão a imagem é recusada com `0xC000007B` |
| [scripts/verify-dump.mjs](scripts/verify-dump.mjs) | Compara o dump reconstruído com o **original em claro** (relocando o original para a base do dump) e classifica cada byte diferente: IAT/LOAD_CONFIG/TLS (o loader preenche), estado de carga (cookie) — e `CODIGO`/`dados`, que é o que se investiga. Sem original, entra em **MODO FRACO**: resíduo de `0xCC`, byte parado no tempo nos endereços do `--bp-log` e faixa ainda cifrada — substituto declarado, não prova de que o dump está limpo |
| [scripts/make-packed-sample.mjs](scripts/make-packed-sample.mjs) | Fabrica um alvo empacotado de estudo (XOR do código, IAT por DLL, salto EP → stub → OEP) a partir de um PE que roda |
| [scripts/load-snaps.ps1](scripts/load-snaps.ps1) | Liga/desliga *loader snaps* (o efeito de `gflags /i app.exe +sls`) para ver a decisão do loader — exige shell elevado |
| [scripts/capture-debugprint.ps1](scripts/capture-debugprint.ps1) | Listener do canal `DBWIN_BUFFER` (saída de depuração de alvos fora do debugger), sem DebugView e sem GUI — validado por auto-teste |
| [scripts/smoke-mcp.mjs](scripts/smoke-mcp.mjs) | Prova que a ponte MCP do REA sobe e responde (handshake `initialize` + `tools/list`) |
| [scripts/start-x64dbg.ps1](scripts/start-x64dbg.ps1) | Sobe o x64dbg minimizado para o plugin MCP ficar vivo, espera a porta e (com `-Check`) roda a chamada MCP real |
| [scripts/mcp-x64dbg-smoke.mjs](scripts/mcp-x64dbg-smoke.mjs) | Prova que o MCP do x64dbg responde **ao vivo** (initialize → tools/list → uma tool real) |
| [scripts/check-consistency.mjs](scripts/check-consistency.mjs) | Teste de regressão offline: doc ↔ código ↔ licenças divergindo, comando/cliente/perfil inexistente |
| [scripts/verify-licenses.mjs](scripts/verify-licenses.mjs) | Confere cada licença declarada contra a fonte primária (rede; job de CI), com retry limitado em host instável — sem afrouxar a verificação |
| [scripts/new-case.ps1](scripts/new-case.ps1) | Cria o esqueleto de um caso em `work/<alvo>/` com procedência e hash |
| [scripts/setup-ghidra-extensions.ps1](scripts/setup-ghidra-extensions.ps1) | Instala a extensão Jython e prepara PyGhidra (Python 3) |
| [scripts/re-build.ps1](scripts/re-build.ps1) | Compila os componentes locais da fonte (REA, x64dbg-MCP) — opcional; o fetch usa releases |
| [scripts/scan-secrets.ps1](scripts/scan-secrets.ps1) | Bloqueia tokens/segredos antes do commit (roda no CI) |

---

## 5. Convenções

- **Diretórios existentes não são movidos.** `ghidra/`, `rea-main/`, `x64dbg/`,
  `x64dbg-mcp-server-main/` continuam na raiz — mover instalação funcionando é
  risco sem ganho. Novas ferramentas vão para `tools/<nome>/`.
  O motivo e a alternativa (migração opcional) estão em
  [docs/01-arquitetura.md](docs/01-arquitetura.md#3-por-que-não-movemos-os-diretórios-existentes).
- **Scripts:** `kebab-case.ps1` / `.sh` / `.mjs`. Todo script aceita `-DryRun`
  (ou `--dry-run`) e nunca assume privilégio administrativo silenciosamente.
- **Docs:** numerados, em PT-BR, com comandos copiáveis e *verificação* ao final de
  cada seção.
- **Idioma de código:** identificadores e comentários em inglês; documentação em PT-BR.
- **Saídas:** todo artefato de análise vai para `work/<alvo>/` (ignorado no Git);
  relatórios consolidados para humanos vão em `reports/`.

---

## 6. Licença e atribuições

O código próprio deste repositório (scripts, docs, configs) é **MIT** — ver
[LICENSE](LICENSE), © UnboxRE contributors.

Ferramentas de terceiros mantêm suas próprias licenças e **não são redistribuídas**
aqui; são instaladas localmente pelo bootstrap. Todo o crédito pertence aos seus
autores — autor, licença e upstream de **cada projeto** referenciado estão em
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). O UnboxRE é independente e **não é
afiliado nem endossado** por nenhum deles.

> Se você for usar o UnboxRE para empacotar algo, publique apenas o que é seu (MIT).
> Redistribuir ferramenta de terceiro exige cumprir a licença dela — a matriz de
> compatibilidade está em [docs/03-licencas.md](docs/03-licencas.md).
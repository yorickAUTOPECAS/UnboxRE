# 00 — Diagnóstico do setup atual

Auditoria executada em **2026-10-13** sobre `C:\Users\Admin\Desktop\UnboxRE`.
Todo achado abaixo tem o comando de reprodução. Nada aqui é suposição: foi rodado.

> **Correção posterior (2026-10-13, pós-`fetch-tools`).** Três achados desta tabela
> deixaram de valer depois que o `fetch-tools.ps1` e a instalação via **release** do
> MCP entraram: (G1) o REA passou a ser instalado do tarball npm e roda —
> `node rea-main/scripts/rea.mjs doctor` reporta `ghidra: healthy`; (G3) o plugin MCP
> **não exige mais Zig** — o release pré-compilado do upstream fornece o `.dp64/.dp32`;
> (G2) os submódulos do REA não são necessários para o provedor Ghidra. Este documento
> fica como registro histórico da auditoria original; o estado vivo está em
> `scripts/health-check.ps1` e no [README](../README.md) §2.

---

## 1. Inventário real do que existe

```
UnboxRE/
├── ghidra/
│   ├── ghidra_12.1.4_PUBLIC/     # 12.1.4, build 20260921, Java min 21 / compile 21
│   └── jdk-27/                   # OpenJDK/Oracle JDK 27 (2026-09-15)
├── rea-main/                     # fonte do REA (rea-agents 6.4.0), MIT — NÃO construído
├── x64dbg/                       # snapshot 2026-05-27 (commit 9c8ca1c)
│   ├── release/x32|x64/          # binários + x96dbg.exe + headless.exe
│   └── pluginsdk/                # SDK C++ (inclui _scriptapi*.h)
└── x64dbg-mcp-server-main/       # fonte Zig do plugin MCP 1.0.0, MIT — NÃO compilado
```

### Evidência

| Comando | Resultado |
|---|---|
| `cat ghidra/ghidra_12.1.4_PUBLIC/Ghidra/application.properties` | `application.version=12.1.4`, `application.java.min=21`, `application.java.max=` (vazio ⇒ sem teto) |
| `cat ghidra/jdk-27/release` | `JAVA_VERSION="27"`, `OS_ARCH="x86_64"` |
| `ls ghidra/ghidra_12.1.4_PUBLIC/Ghidra/Features/Decompiler/os` | `linux_x86_64`, `win_x86_64` ⇒ **decompilador nativo Windows presente** |
| `cat x64dbg/commithash.txt` | `9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87` |
| `head x64dbg/release/release-notes.md` | release de maio/2026 (hotfix) |
| `ls rea-main/dist` | *inexistente* |
| `ls -d rea-main/node_modules` | *inexistente* |
| `ls -A rea-main/third_party/*` | `binwalk, unblob, jadx-headless-mcp, ghidra-nativeaot, wakaru` ⇒ **0 arquivos** (submódulos não inicializados) |
| `ls rea-main/native/windows/build` | *inexistente* (falta `rea-windows-x64.node`) |
| `ls x64dbg/release/x64/plugins` | *inexistente* (MCP server não pode carregar) |

---

## 2. Toolchain do host

| Ferramenta | Estado | Versão / nota |
|---|---|---|
| Node.js | ✅ | v24.18.0 — **dentro** do suportado pelo REA (`^22.19 \|\| ^24.11 \|\| >=26`) |
| npm | ✅ | 11.16.0 — bate exatamente com `packageManager` do REA |
| Python | ⚠️ | `python` 3.11.15 (do venv do hermes) · `py` 3.12.9 (Python312) · `python3` **quebrado** (alias da Microsoft Store) |
| Java | ✅ | 21.0.12 LTS no `PATH` + JDK 27 em `ghidra/jdk-27` |
| Git | ✅ | 2.55.0.windows.2 |
| Rust | ✅ | cargo/rustc 1.98.1 |
| PowerShell | ✅ | Windows PowerShell **5.1** (sem `pwsh` 7) — scripts são escritos para 5.1 |
| winget | ✅ | disponível |
| Chocolatey | ✅ | disponível |
| WSL | ⚠️ | binário presente, **nenhuma distro instalada** |
| uv | ✅ | 0.11.32 (gerenciador Python moderno) |
| **Zig** | ❌ | ausente ⇒ **bloqueia build do x64dbg-MCP** |
| **7-Zip / cmake / gcc / clang / go / dotnet** | ❌ | ausentes ⇒ bloqueiam unpack de firmware, build nativo e tooling .NET |
| Scoop | ❌ | ausente (opcional; winget+choco cobrem) |

Disco: **114 GB livres** em `C:` — suficiente para o stack completo (WSL+VM é o
maior consumidor; reserve ~60 GB se for rodar VMs com snapshots).

---

## 3. Gaps de capacidade — o que você **não consegue** fazer hoje

### 3.1 Bloqueios duros (nada funciona sem resolver)

| # | Gap | Impacto | Causa-raiz | Correção |
|---|---|---|---|---|
| G1 | **REA não executável** | Perde a camada de orquestração/agente que unifica Ghidra, Android, firmware, rede, JS/Electron | Fonte sem `npm install` + sem build | `npm ci && npm run build` (scripts/re-build.ps1) |
| G2 | **Submódulos do REA vazios** | Integrações de firmware (`binwalk`/`unblob`), Android (`jadx-headless-mcp`), NativeAOT (`ghidra-nativeaot`), JS (`wakaru`) falham | `git submodule` não inicializado | `git submodule update --init --recursive` |
| G3 | **x64dbg-MCP não compilado** | Sem debug controlado por IA — o diferencial do setup | Zig ausente | instalar Zig 0.14+ e `zig build` |
| G4 | **`x64dbg/release/*/plugins/` não existe** | Nenhum plugin carrega (nem o MCP, nem ScyllaHide, nem xAnalyzer) | x64dbg não cria a pasta | criar + copiar plugins |
| G5 | **Extensão Jython não instalada** | Scripts Ghidra em Python 2 (a maioria dos repositórios públicos) não rodam | o ZIP está em `Extensions/Ghidra/..._Jython.zip`, não extraído | setup-ghidra-extensions.ps1 |
| G6 | **PyGhidra não instalado** (`pip install pyghidra`) | Sem Ghidra via Python 3 nativo — inviável automatizar análise em pipeline Python moderno | pacote ausente | `pip install pyghidra` |
| G7 | **Sem laboratório Linux** | ELF/DWARF, Android, firmware, angr, Qiling, AFL++ — tudo indisponível | WSL sem distro | `wsl --install -d Ubuntu-24.04` |
| G8 | **Sem isolamento de execução** | Analisar amostra desconhecida no host é irreversível | sem VM/sandbox | Windows Sandbox + VM com snapshot |

> **Escopo desta rodada: Windows 10/11.** É aqui que o caminho crítico está validado.
> G7 (laboratório Linux), o debug Linux/macOS e os formatos ELF/Mach-O ficam
> **fora de escopo por ora** — são roadmap, não bloqueios do caminho Windows.

### 3.2 Gaps de cobertura (por domínio pedido)

| Domínio | Cobertura hoje | Falta (crítico primeiro) |
|---|---|---|
| **a) Estática** | Ghidra (x86/x64/ARM/MIPS/RISC-V via `.ldefs`), decompilador nativo | CLI scriptável (radare2/rizin), parsing programático (LIEF/pefile/pyelftools), detecção de compilador/packer (DIE), bindiff (ghidriff/Diaphora), simbólico (angr/Triton), YARA |
| **b) Dinâmica** | x64dbg usermode (GUI + `headless.exe`), sem controle por IA | Kernel debug (WinDbg+TTD), **TTD** (o melhor instrumento para lógica complexa), DBI (Frida/DynamoRIO/TinyInst), emulação (Qiling/Unicorn/Speakeasy), tracing de API/syscall, Linux/macOS (GDB+gef/pwndbg, LLDB) |
| **c) Desobfuscação** | nada | Unpacking (UPX/Scylla nativo do x64dbg já existe, falta o resto), anti-anti-debug (ScyllaHide/TitanHide), detecção de injeção/hollowing (PE-sieve/HollowsHunter/Moneta), MBA/simbólico (msynth/Triton/Miasm/D-810), devirtualização (VTIL/NoVmp), .NET (de4dot/dnlib/NETReactorSlayer), OLLVM (D-810/HexRaysDeob) |
| **d) Formatos** | PE/.NET (via Ghidra+PDB) | ELF/Mach-O completos, APK/DEX, firmware (binwalk/unblob/UEFITool), Java bytecode, WASM, Go/Rust symbol recovery, IL2CPP/Unity |
| **e) Reconstrução** | Ghidra pseudocódigo | Rebuild de IAT (Scylla — presente no x64dbg, falta a receita), dump de processo (PE-sieve), patching scriptável (LIEF), recompilação (RetDec/rev.ng), diff de binários, limpeza de pseudocódigo |
| **f) Automação** | nada | Scripts Ghidra (Java/PyGhidra), `x64dbg-script`, pipelines (`just`/Python), **clientes MCP configurados** |
| **g) Rede** | mitmproxy presente só como *submódulo do REA* | Wireshark/tshark, interceptação TLS em app (Frida unpinning), Kaidai Struct, fuzzing (boofuzz/AFL++), captura de API Windows |

### 3.3 Riscos de versão encontrados na auditoria

1. **JDK 27 vs. alvo verificado.** Ghidra 12.1.4 aceita `>=21` sem teto, então JDK 27
   *abre*. Mas: (a) o REA declara verificação com **JDK 21**; (b) módulos que usam
   reflexão em `java.*` podem estourar com `InaccessibleObjectException` em JDKs
   muito novos. → **Recomendação: manter o JDK 21 LTS do `PATH` como padrão do Ghidra**
   e usar o JDK 27 apenas para projetos que exijam. O `health-check` reporta ambos e
   avisa se o Ghidra resolver para ≠21; `-Fix-Paths` grava o pin no env file.
2. **`python3` da Microsoft Store quebrado.** Ferramentas que chamam literalmente
   `python3` falham em silêncio. → Normalizar via `uv` (gerencia 3.12) e expor um
   shim, ou usar o `py` launcher. O bootstrap valida `python -c "import sys"`.
3. **REA em Windows é "P0" e read-only.** O provider Ghidra do REA no Windows é
   **experimental, somente leitura, apenas PE x86/x86-64** — sem anotação, sem
   renomear. → No Windows, quem anota é o Ghidra GUI ou `analyzeHeadless` com
   scripts; o REA serve para *leitura* e para orquestrar Android/firmware/rede/JS.
   Não conte com `annotate_native_function` no Windows.
4. **x64dbg é GPL-3.0.** Qualquer plugin/binário redistribuído é GPL. Seu toolkit
   publica apenas *scripts e docs* — por isso o `.gitignore` bloqueia binários.
5. **`rea-main` da versão main ≠ pacote npm 6.4.0.** O próprio doc do REA avisa: a
   `main` pode ter recursos ainda não lançados. → Pinamos o build local e mantemos
   `package-lock.json` intacto (nunca `npm install` sem `ci` em CI).
6. **`x64dbg-mcp-server` exige Zig 0.16-dev no README mas `build.zig.zon` declara
   `minimum_zig_version = 0.14.0` e o CI usa 0.14.0.** → **Instalar 0.14.0**
   (a versão que o CI comprova). Versões 0.15/0.16 mudaram APIs e podem quebrar o build.

---

## 4. Integrações possíveis hoje (mesmo sem instalar nada novo)

| Integração | Como | Ganho |
|---|---|---|
| **Ghidra ↔ REA** | `GHIDRA_INSTALL_DIR` + `JAVA_HOME` → `rea doctor --provider ghidra` | Análise estática semântica ("o que esta função faz") via linguagem natural, com evidência estruturada |
| **x64dbg ↔ IA** | plugin MCP (porta 9094/9095) | Stepping, breakpoints, memória, dump, OEP — tudo por linguagem natural |
| **Ghidra ↔ x64dbg** | mesmo alvo dos dois lados; sincronizar base pelo `AnalyzeModule` (x64dbg) e rebase no Ghidra | Navegação cruzada estático↔dinâmico |
| **x64dbg headless ↔ CI** | `release/x64/headless.exe` + `_scriptapi` | Debug automatizado sem GUI para regressão |
| **Ghidra `analyzeHeadless` ↔ pipeline** | `-postScript` + `-log` | Análise em lote e geração de relatórios |
| **MCP server ↔ qualquer cliente** | `gen-mcp-config.mjs` | Um único ponto de verdade das configs |

---

## 5. Plano de correção (ordem de execução)

```
Fase 0 — Higiene (5 min)          : .gitignore, LICENSE, estrutura de docs   [FEITO nesta entrega]
Fase 1 — Destravar o existente    : G1 G2 G3 G4 G5 G6   →  scripts/re-build.ps1 + bootstrap -Profile core
Fase 2 — Isolamento               : G8 (VM + Windows Sandbox) + Fase 0 de higiene de rede
Fase 3 — Estática profissional    : radare2/rizin, LIEF, capstone, YARA, DIE, ghidriff, angr
Fase 4 — Dinâmica profissional    : Frida, DynamoRIO/TinyInst, WinDbg+TTD, ScyllaHide, PE-sieve, Moneta
Fase 5 — Laboratório Linux        : G7 → WSL2 Ubuntu 24.04 + toolchain ELF/Android/firmware/fuzzing
Fase 6 — Rede e protocolos        : Wireshark, Kaitai, boofuzz, unpinning via Frida
Fase 7 — Automação e MCP          : configs de cliente, pipelines `just`, relatórios automáticos
```

Cada fase termina com `health-check.ps1` verde naquele perfil. Se um check falhar,
**não avance** — as fases 3–7 assumem as anteriores.

---

## 6. Como revalidar esta auditoria

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\health-check.ps1 -Json | Tee-Object reports\health-latest.json
node .\scripts\gen-mcp-config.mjs --check
```

O relatório JSON inclui, por item: `id`, `category`, `status`
(`ok|warn|missing|blocked`), `detail`, `fix`. Esse formato é o contrato consumido
pelas instruções de operação por IA em [07-operacao-por-ia.md](07-operacao-por-ia.md).
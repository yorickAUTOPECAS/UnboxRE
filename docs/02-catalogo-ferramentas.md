# 02 — Catálogo exaustivo de ferramentas

Catálogo por domínio. Cada entrada responde às cinco perguntas que um agente (ou
você, seis meses depois) precisa: **o que faz**, **quando usar**, **como usar**,
**integração** com o resto do setup e **licença**.

> **Como ler os comandos.** `PS>` = PowerShell no host Windows. `$` = bash (Git Bash
> ou WSL). `r2>` = prompt do radare2. `ghidra>` = script Ghidra. Caminhos assumem a
> raiz do toolkit (`C:\Users\Admin\Desktop\UnboxRE`) e as variáveis de
> [config/env/unboxre.env.example](../config/env/unboxre.env.example).

---

## 0. Legenda de licença e de disponibilidade

| Marca | Significado |
|---|---|
| `MIT` `BSD-2` `BSD-3` `Apache-2.0` `ISC` `Unlicense` | permissiva — **MIT-compatível**; pode-se redistribuir código próprio que a consuma |
| `LGPL-x` | uso como biblioteca/CLI separada é ok; modificar e distribuir *a própria lib* exige liberar as mudanças |
| `GPL-x` | copyleft forte — **não** redistribuir junto com o seu código MIT no mesmo binário; chamar via CLI/processo é aceitável (ver [03-licencas.md](03-licencas.md)) |
| `[COMERCIAL]` | sem alternativa aberta equivalente madura; requer licença paga |
| `[FREEMIUM]` | versão gratuita funcional + versão paga para casos avançados |
| `✅ já instalado` | presente no setup auditado |
| `⬜ a instalar` | entra pelo bootstrap |

**Regra de ouro do catálogo:** se existe uma alternativa permissiva madura, ela vem
primeiro; a opção comercial aparece como *upgrade consciente*, nunca como requisito.

---

## 1. Camada 0 — Núcleo (o que você já tem)

Estas quatro ferramentas são a base; tudo o resto se integra a elas.

### 1.1 Ghidra 12.1.4 `✅ já instalado`

| Campo | Valor |
|---|---|
| **O que faz** | Suíte SRE da NSA: descompilador multi-arquitetura, análise automática, CFG/call graph, data flow, scripting (Java + Python via PyGhidra/Jython), headless para lote |
| **Quando usar** | Análise estática de *qualquer* binário: x86/x64/ARM/AArch64/MIPS/PPC/RISC-V/SPARC/6502/etc. É o **cavalo de batalha** do toolkit — descompilador de graça, sem limite de tamanho |
| **Arquiteturas** | ~25 processadores via `.ldefs`; verifique com `ls ghidra/ghidra_12.1.4_PUBLIC/Ghidra/Processors` |
| **Como usar (GUI)** | `PS> .\ghidra\ghidra_12.1.4_PUBLIC\ghidraRun.bat` |
| **Como usar (headless)** | ver bloco abaixo |
| **Licença** | Apache-2.0 (o descompilador nativo tem licença própria, uso livre) |

```bash
# Análise headless completa de um alvo, com script de pós-processamento
$ export JAVA_HOME="$PWD/ghidra/jdk-27"      # ou o JDK 21 do PATH (recomendado)
$ ghidra/ghidra_12.1.4_PUBLIC/support/analyzeHeadless.bat \
    work/acme-cad/ghidra-proj  acme-cad \
    -import work/acme-cad/src/target.exe \
    -postScript ExportPseudocode.java \
    -scriptPath work/acme-cad/scripts \
    -deleteProject -log work/acme-cad/notes/ghidra.log
```

**Integração:** `GHIDRA_INSTALL_DIR` alimenta o REA; `analyzeHeadless` alimenta o
pipeline (`scripts/re-build.ps1` → `work/<alvo>/notes/static.md`); a GUI e o x64dbg
compartilham o mesmo alvo (rebase pela base do `AnalyzeModule`).

### 1.2 x64dbg (snapshot 2026-05-27) `✅ já instalado`

| Campo | Valor |
|---|---|
| **O que faz** | Debugger usermode Windows x32/x64: stepping, breakpoints (INT3/hardware/memória/condicional), patching, análise, script engine, `headless.exe` para automação |
| **Quando usar** | Todo cenário dinâmico em Windows: unpacking, tracing de API, encontrar checks, inspecionar memória viva, patch rápido |
| **Como usar** | `PS> .\x64dbg\release\x96dbg.exe` (GUI) · `PS> .\x64dbg\release\x64\headless.exe -a script.txt` (CI) |
| **Licença** | GPL-3.0 — **não** redistribuir binários no seu repo MIT |

**Integração:** hospeda o plugin MCP (controle por IA); a pasta `plugins/` precisa
existir (G4 no diagnóstico); ScyllaHide/Scylla/xAnalyzer entram nela.

### 1.3 REA 6.4.0 (`rea-main/`) `⬜ não construído`

| Campo | Valor |
|---|---|
| **O que faz** | Camada de **orquestração por agente** sobre Ghidra/IDA/JEB/Hopper + Android/firmware/rede/JS/Electron/WASM/.NET. Expõe MCP, skills e um contrato de *evidência* |
| **Quando usar** | Quando você quer "o que esta função faz?" em linguagem natural, com evidência rastreável; análise Android/firmware/rede em lote; reconstrução de apps JS/Electron |
| **Como usar** | `PS> node .\rea-main\scripts\rea.mjs --help` · `... rea doctor` · `... rea mcp` |
| **Licença** | MIT (o próprio REA); os submódulos têm licenças próprias |

**Limitação crítica no Windows:** o provider Ghidra é **P0, somente leitura, só PE
x86/x64** ([rea-main/docs/windows-ghidra-p0.md](../rea-main/docs/windows-ghidra-p0.md)).
Anotação/renomeação só via Ghidra GUI ou headless.

### 1.4 x64dbg-MCP Server 1.0.0 `⬜ não compilado`

| Campo | Valor |
|---|---|
| **O que faz** | Plugin nativo (Zig) dentro do x64dbg que expõe **~72–84 ferramentas** de debug via MCP/HTTP: stepping, breakpoints, memória, patches, dump, OEP, PEB, tracing, xrefs |
| **Quando usar** | Qualquer operação dinâmica conduzida por IA — é o que transforma o x64dbg em "mãos" do agente |
| **Como usar** | compilar (`scripts/re-build.ps1`), copiar `dist/` para `x64dbg/`, configurar `gen-mcp-config.mjs`, porta 9094 (x64)/9095 (x32), Bearer token em `mcp_config.json` |
| **Licença** | MIT |

**Integração:** é o ponto de entrada dinâmico dos clientes MCP. Ver [05-mcp.md](05-mcp.md).

---

## 2. Domínio (a) — Análise estática

Além do Ghidra, o que falta para análise estática *profissional e scriptável*.

### a.1 radare2 + rizin `⬜` — `LGPL-3.0`

- **O que faz:** framework de análise por CLI/script (r2pipe), disassembly, CFG, xrefs, ESIL (IR para emulação leve), patching, `r2 -A` (análise automática). Rizin é o fork moderno.
- **Quando usar:** quando a **velocidade e o script** importam mais que o pseudocódigo; grep semântico em centenas de binários; automação em Python (`r2pipe`).
- **Como usar:**
  ```bash
  $ r2 -A -q -c 'afl~main; pdf @ main' work/acme-cad/src/target.exe
  $ r2 -A -q -c 'izz~http' target.exe        # strings
  $ r2 -A -q -c 'axt @ 0x401000' target.exe  # xrefs
  ```
- **Integração:** `r2pipe` para pipelines Python; o REA usa radare2 como fallback; `rabin2` para metadados de formato (entra na triagem).
- **Por quê:** o Ghidra é ótimo mas *pesado*; r2/rizin é o que roda em loop de 10.000 arquivos.

### a.2 LIEF `⬜` — `Apache-2.0`

- **O que faz:** biblioteca Python/C++ para **ler e reescrever** PE/ELF/Mach-O/OAT/DEX. Alterar seções, imports, entrypoint, TLS callbacks, resources — e salvar o binário.
- **Quando usar:** inspeção programática de headers; **patching scriptável**; reconstruir/limpar tabela de imports; instrumentar binários (adicionar seção).
- **Como usar:**
  ```bash
  $ uv pip install lief
  $ python -c "import lief;p=lief.parse('target.exe');print(p.header.machine_type,p.entrypoint)"
  $ python work/<alvo>/scripts/patch-entry.py   # script DO CASO, não do toolkit (docs/01 §2)
  ```
- **Integração:** entrada/saída do pipeline (parseia o que o Ghidra analisou); alimenta o `04-instalacao` de patching.

### a.2.1 `triage-static.mjs` `✅ do toolkit` — `MIT`

- **O que faz:** a mesma pergunta do LIEF/DIE respondida **sem terceiro e sem debugger**, nos
  dois formatos: cabeçalho, seções com permissões e entropia, imports (por DLL no PE;
  `DT_NEEDED` + símbolos indefinidos do `.dynsym` no ELF), o código que roda **antes** do
  `main` (TLS callbacks no PE; `DT_INIT`/`DT_INIT_ARRAY` no ELF), strings **só de seções não
  executáveis** com o endereço de cada uma e, com `--refs`, onde cada uma é usada no código;
  com `--data-refs`, as **constantes** que o código lê (semente, máscara, tabela).
- **Quando usar:** primeiro passo de toda triagem, e de novo a cada passo do "o que ele
  imprime / o que ele importa / onde isso é usado". É o que a rodada 8.1 escreveu na mão
  para um crackme de 13 KB e a rodada 8.3 precisou para um ELF — nas duas vezes porque o
  caminho existente (`GetStrings`/`GetImports` do MCP) exige o debugger vivo.
- **Como usar:**
  ```bash
  $ node scripts/triage-static.mjs <alvo> --refs            # strings e onde são usadas
  $ node scripts/triage-static.mjs <alvo> --data-refs       # que CONSTANTES o código lê
  ```
- **Integração:** alimenta `notes/triage.md`; os endereços que ele imprime são o que
  `pe-read.mjs` lê e o que `disasm-range.py` desmonta. No ELF, o endereço é o **vaddr de
  link** (absoluto, como no readelf), não um RVA.
- **Por quê:** o `diec` é ótimo para "é packer", mas não responde "qual string este alvo
  imprime e qual instrução a usa" — e essa é a pergunta que decide o próximo comando.

### a.3 Capstone + Keystone `⬜` — `BSD-3`

- **O que faz:** Capstone = **disassembler** programático multi-arch; Keystone = **assembler** programático.
- **Quando usar:** dentro de scripts Python (parsear um trace, montar um stub, desmontar bytes de memória do x64dbg/Frida).
- **Como usar:** `python -c "from capstone import *;print(Cs(CS_ARCH_X86,CS_MODE_64).disasm(b'\x48\x31\xc0',0x1000).__next__())"`
  e, no toolkit, `python scripts/disasm-range.py <alvo> <rva-ini> --fim <rva-fim> --strings`
  (o caminho entre a triagem e o debugger: lê o trecho de código sem abrir Ghidra — aceita
  **PE e ELF**; no ELF o endereço é o vaddr de link).
- **Integração:** base de quase todo script de análise custom; usado por angr/Qiling.
- **Instalação (medida no round 8.1):** o Capstone **não tem comando próprio** — o
  `cstool` não vem no pacote do pip — então nem o `health-check` nem o bootstrap o
  enxergavam: entra agora pela entrada `Capstone` do perfil `static`
  (`python -m pip install --user capstone`), sondado por **módulo Python** (`PyModule`).
  Keystone continua só no caminho Linux (`bootstrap-wsl.sh`, `keystone-engine`) — não há
  consumidor dele no Windows hoje.

### a.4 YARA + yara-x `⬜` — `BSD-3` / `Apache-2.0`

- **O que faz:** regras de padrão sobre arquivos/memória (bytes, strings, condições booleanas). `yara-x` é a reimplementação Rust, mais rápida.
- **Quando usar:** classificar famílias/packers; detectar bibliotecas de terceiros (identificar o que é *seu* vs. *vendor*); varrer diretórios grandes.
- **Como usar:** `$ yara -r rules/ target.exe` · `$ yr scan rules/ target.exe` (yara-x)
- **Integração:** passo de triagem automática; regras próprias em `config/yara/`.

### a.5 Detect It Easy (DIE) + `diec` `⬜` — `MIT`

- **O que faz:** detecta **packer, compilador, linker, protetor** (UPX, Themida, VMProtect, Enigma, ASPack, PECompact, OLLVM, .NET obfuscators…) e entropia por seção. `diec` é a CLI.
- **Quando usar:** **primeiro passo de toda triagem** — decide se você analisa estático ou precisa unpackar antes.
- **Como usar:** `$ diec -j target.exe > notes/die.json`
- **Integração:** saída JSON alimenta `notes/triage.md`; define se o passo 3 (unpack) é obrigatório.
- **Por quê:** sem DIE você descobre que era VMProtect depois de 3 horas de Ghidra.
- **Primeira passada embutida (sem DIE):** `node scripts/identify-protections.mjs <alvo>`
  cobre UPX/VMProtect/Themida/ASPack/MPRESS/Enigma/.NET por assinatura e estrutura — e,
  desde a rodada 8.3, **também ELF** (segmento LOAD W+X, entry fora do LOAD, `ptrace`
  importado, `UPX!`); o DIE continua sendo o passo mais completo.

### a.6 ghidriff + Diaphora `⬜` — `Apache-2.0` / `GPL-3.0`

- **O que faz:** **bindiff** — diff de dois binários (v1 vs v2, patch vs original), casando funções por hash semântico.
- **Quando usar:** "o que mudou na versão 2.4?"; achar a função nova que implementa a feature nova; detectar patch de segurança.
- **Como usar:** `$ ghidriff old.exe new.exe -o work/acme-cad/diff/` (usa Ghidra headless por baixo)
- **Integração:** consome projetos Ghidra; produz relatório de funções adicionadas/removidas/alteradas.

### a.7 angr + Triton `⬜` — `BSD-2`

- **O que faz:** execução **simbólica** e concolic — resolve "qual entrada faz o check passar?" sem rodar o binário.
- **Quando usar:** desviar de checks de licença/serial sem brute force; resolver constraints de VM custom; entender algoritmos obscuros.
- **Como usar:**
  ```python
  import angr; p = angr.Project("target.exe", auto_load_libs=False)
  st = p.factory.entry_state(); sm = p.factory.simulation_manager(st)
  sm.explore(find=0x401500, avoid=0x401600)   # achar sucesso, evitar falha
  print(sm.found[0].posix.dumps(0))           # entrada que satisfaz
  ```
- **Integração:** alimenta o passo 7 (reconstrução) com *a lógica exata* do check, não uma aproximação.
- **Por quê:** é o instrumento que mais economiza tempo humano em checks complexos.

### a.8 de4dot-cex / dnlib `⬜` — `MIT`

- **O que faz:** deobfuscação de **.NET** (ConfuserEx, SmartAssembly, Dotfuscator, Eazfuscator…) e biblioteca para ler/escrever assemblies.
- **Quando usar:** qualquer alvo gerenciado (C#/VB.NET) — o IL é o "código-fonte" quase direto.
- **Como usar:** `$ de4dot-cex target.exe -o target-clean.exe` → depois dnSpyEx/ILSpy
- **Integração:** entra em `docs/04-instalacao.md` (perfil `formats`); alimenta análise estática de .NET.

### a.9 ImHex `⬜` — `GPL-2.0`

- **O que faz:** editor hexadecimal com **patterns** (linguagem própria para estruturar formato de arquivo) e desassembler integrado.
- **Quando usar:** reverter **formato de arquivo proprietário** (documento, save, asset); visualizar estruturas de firmware.
- **Como usar:** abrir o arquivo, carregar um `.hexpat` em `config/imhex-patterns/`.
- **Integração:** combinado com Kaitai (g), cobre formato-de-arquivo de ponta a ponta.

### a.10 bindiff comerciais `[COMERCIAL]`

- **BinDiff (Google)** e **Diaphora** (GPL, grátis) — BinDiff é mais rápido em escala, Diaphora mais detalhado. Use ghidriff/Diaphora como padrão aberto.

---

## 3. Domínio (b) — Análise dinâmica

### b.1 WinDbg + Time Travel Debugging (TTD) `⬜` — `[COMERCIAL]` (grátis no WinDbg)

- **O que faz:** debugger da Microsoft com **kernel mode**, crash dump analysis e **TTD** — grava a execução e permite *voltar no tempo*.
- **Quando usar:** **TTD é o melhor instrumento para lógica complexa**: rode uma vez, depois navegue para frente e para trás até entender. Kernel drivers, bugs intermitentes, algoritmos com estado.
- **Como usar:**
  ```powershell
  PS> winget install Microsoft.WinDbg
  PS> windbgx -c "g" target.exe            # ou abrir e usar o botão "Record"
  # no WinDbg: !tt 0  (vai para o início), p/pp (step), g- (volta no tempo)
  ```
- **Integração:** o `.run` (trace TTD) vira artefato em `work/<alvo>/captures/`; complementa o x64dbg (que é melhor em GUI/patching).
- **Por quê:** nenhuma outra ferramenta responde "como chegamos a este estado?" tão bem.

### b.2 Frida `⬜` — `wxWindows` (LGPL-like) / `MIT` (bindings)

- **O que faz:** **instrumentação dinâmica** (DBI) — injeta JS no processo, intercepta funções, lê/escreve memória, hook em qualquer endereço/símbolo, funciona em Windows/Linux/macOS/Android/iOS.
- **Quando usar:** hooking de API sem rebuild; **unpinning de TLS** (interceptar tráfego mesmo com pinning); dump de chaves; observar argumentos de função em runtime; automação Android.
- **Como usar:**
  ```bash
  $ frida-trace -i "CreateFileW" -i "RegOpenKey*" target.exe
  $ frida -l hooks/crypto-dump.js -f target.exe
  $ frida-ps -Uai                 # apps Android no device USB
  ```
- **Integração:** o REA usa Frida no bridge `process`; scripts próprios em `work/<alvo>/scripts/`.

### b.3 DynamoRIO + TinyInst + DrMemory `⬜` — `BSD-3` / `Apache-2.0`

- **O que faz:** frameworks **DBI** para construir clientes de instrumentação (trace de instruções, taint, cobertura) sem tocar no alvo.
- **Quando usar:** tracing de altíssimo volume (milhões de instruções); **cobertura de código** (fuzzing feedback); taint analysis.
- **Como usar:** `$ drrun -c drcov -- target.exe` → `drcov2lcov` → cobertura.
- **Integração:** TinyInst é a base do **WinAFL** (fuzzing Windows); alimenta o domínio (g).

### b.4 Unicorn + Qiling + Speakeasy `⬜` — `GPL-2.0` / `GPL-2.0` / `Apache-2.0`

- **O que faz:** **emulação de CPU** (Unicorn = só CPU; Qiling = CPU + OS + syscalls; Speakeasy = emulação de API Windows).
- **Quando usar:** rodar **shellcode** e trechos de código sem o resto do binário; emular **firmware** (MIPS/ARM) sem hardware; desviar de anti-debug/anti-VM; análise de amostra sem risco.
- **Como usar:**
  ```python
  from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
  uc = Uc(UC_ARCH_X86, UC_MODE_64); uc.mem_map(0x1000, 0x1000)
  uc.emu_start(0x1000, 0x1000 + len(code))
  ```
  ```bash
  $ qltool run -f rootfs/mips --rootfs rootfs/mips firmware.bin
  ```
- **Integração:** Qiling é o caminho para firmware (d); Unicorn é a base do angr.

### b.5 GDB + gef/pwndbg, LLDB `⬜` — `GPL-3.0` / `Apache-2.0`

- **O que faz:** debug nativo em Linux (GDB+gef/pwndbg) e macOS (LLDB).
- **Quando usar:** ELF e Mach-O — no WSL para Linux, no host macOS.
- **Como usar:** `$ gdb -q ./target` → `gef> vmmap`, `gef> telescope $rsp`, `gef> hexdump`.
- **Integração:** dentro do WSL (perfil `wsl`); o REA tem bridge `pwndbg`/`pwntools`.

### b.6 ScyllaHide + TitanHide `⬜` — `GPL-3.0`

- **O que faz:** **anti-anti-debug**: esconde o debugger do alvo (PEB, NtGlobalFlag, DRx, timing, exceptions).
- **Quando usar:** alvo detecta o x64dbg e termina/sai. Instale como plugin **antes** de culpar sua análise.
- **Como usar:** copiar para `x64dbg/release/{x32,x64}/plugins/`; configurar o perfil no menu.
- **Integração:** plugin do x64dbg (a pasta G4).

### b.7 PE-sieve + HollowsHunter + Moneta `⬜` — `BSD-2` / `BSD-2` / `GPL-3.0`

- **O que faz:** detecta **injeção, hollowing, hooking, código não mapeado** em processo vivo; dump de regiões suspeitas.
- **Quando usar:** alvo self-injecting/process-hollowing; validar se há código escondido; extrair o "payload real" já desempacotado da memória.
- **Como usar:** `$ pe-sieve64.exe /pid 1234 /shellc /dir work/acme-cad/unpacked`
- **Integração:** complementa o `DumpModule` do x64dbg-MCP; artefatos vão para `unpacked/`.
- **Atribuição:** PE-sieve e HollowsHunter — hasherezade (BSD-2); Moneta — Forrest Orr, <https://github.com/forrest-orr/moneta> (GPL-3.0).

### b.8 Sysinternals (Procmon, Process Explorer, TCPView, Autoruns) `⬜` — `[COMERCIAL]` (grátis, EULA Microsoft)

- **O que faz:** observação de **comportamento**: arquivos/registro/rede por processo.
- **Quando usar:** **primeiro passo dinâmico** de qualquer alvo Windows — o Procmon mostra o que o alvo *faz* antes de você abrir o debugger.
- **Como usar:** `$ procmon /Quiet /Minimized /BackingFile trace.pml` → `procmon /OpenLog trace.pml /SaveAs trace.csv`
- **Integração:** `trace.csv` em `captures/`; define os pontos de breakpoint que você vai usar no x64dbg.
- **Atribuição:** Microsoft (Sysinternals) — licença própria, `LicenseRef-Microsoft-Sysinternals-EULA` em `config/licenses.json`.

### b.9 gflags (Global Flags Editor) + loader snaps `⬜` — `[COMERCIAL]` (grátis, EULA Microsoft)

- **O que faz:** liga o **`+sls` — “Show loader snaps”** (`FLG_SHOW_LDR_SNAPS = 0x02`): o loader do `ntdll` imprime cada passo da montagem da imagem (mapeamento, seções, imports, relocations, dependências e a decisão final).
- **Quando usar:** **um `.exe` é recusado pelo Windows antes do entrypoint** (`0xC000007B`, `0xC0000135`, `0xC0000142`). Sem snaps só existe o sintoma — nada dentro do processo roda, logo não há backtrace nem log. Ver [../reports/root-cause-0xc000007b.md](../reports/root-cause-0xc000007b.md).
  Se o alvo for um **dump de memória** (não um packer), o suspeito nº 1 é o **estado de carga**: o `__security_cookie` já randomizado faz `LdrInitSecurityCookie` devolver 0 e o loader reprovar a imagem — meça com `diagnose-load.mjs` e conserte com `scripts/reset-load-state.mjs`. A cadeia medida (breakpoint + registrador + valor) está no §8 do mesmo relatório.
- **Como usar (sem instalar nada — o caminho que este toolkit usa):**
  ```powershell
  PS> .\scripts\diagnose-load.mjs alvo.exe                 # o que está torto no PE
  PS> .\scripts\load-snaps.ps1 -Image alvo.exe -Apply      # em shell ELEVADO (escreve HKLM)
  PS> .\scripts\capture-debugprint.ps1 -Seconds 30 -OutFile work\alvo\evidence\loadsnaps.txt
  PS> # iniciar alvo.exe em outra janela, durante os 30 s
  PS> .\scripts\load-snaps.ps1 -Image alvo.exe -Disable -Apply   # desligar ao terminar
  ```
  Com o gflags instalado, a equivalência é `gflags /i alvo.exe +sls`.
- **Integração:** a saída vai para `evidence/` e é interpretada depois (regra do projeto); alimenta o veredito de `diagnose-load.mjs` e o `docs/06-workflows.md` (dump recusado). Leitores: x64dbg, WinDbg, `capture-debugprint.ps1`.
- **Instalação:** **não existe pacote no winget** (`winget search "debugging tools"` → nada) e o pacote do WinDbg **não traz** `gflags.exe` (medido: os `.exe` do pacote são `createdump`, `DbgX.Mcp.Proxy`, `DbgX.Shell`, `DebuggerCredentialManager`). O gflags vem do componente *Debugging Tools for Windows* do Windows SDK/WDK — por isso o par `load-snaps.ps1` + `capture-debugprint.ps1` existe: mesmo efeito, sem instalar o SDK.
- **Atribuição:** Microsoft (Debugging Tools for Windows) — `LicenseRef-Microsoft-SDK-WDK-EULA` em `config/licenses.json`. Ficha completa: [tools/gflags.md](tools/gflags.md).

---

## 4. Domínio (c) — Desobfuscação e bypass de proteções

### c.1 Packer/unpacker

| Ferramenta | O que faz / quando usar | Como usar | Licença |
|---|---|---|---|
| **UPX** | desempacotar UPX (`-d`); detectar com DIE | `$ upx -d packed.exe -o unpacked.exe` | `GPL-2.0` |
| **Scylla** | **reconstruir IAT** após unpack manual (já no x64dbg como plugin) | no x64dbg: menu Scylla → IAT Autosearch → Get Imports → Dump | `GPL-3.0` |
| **`rebuild-iat.mjs` + `verify-dump.mjs`** (deste toolkit) | equivalente **headless** e auditável do *Fix Dump*, mais a verificação que o Scylla não faz: compara o resultado com o original em claro (relocando o original para a base do dump) e separa "o loader preenche" de "defeito". **Sem original** (crackme/alvo comercial), cai no *modo fraco*: `0xCC` residual, byte parado no tempo e faixa ainda cifrada — substituto declarado | `node scripts/rebuild-iat.mjs --dump … --out …` e depois `node scripts/verify-dump.mjs --dump … --original …` (ou `--packed … --bp-log …` sem original) | `MIT` |
| **x64dbg `DetectOEP`** | acha o OEP de packer (já instalado) | MCP: `DetectOEP` → `SetHardwareBreakpoint` no OEP (**não** `SetBreakpoint`: o de software escreve `0xCC` na memória e o stub pode decriptar por cima) → `DumpModule` | `GPL-3.0` |
| **unpacker scripts** | scripts de unpack específicos por packer (Themida/VMProtect são *difíceis*) | usar os do x64dbg Script Store em `work/<alvo>/scripts/` | variada |
| **VMProtect/Themida/Enigma** | `[COMERCIAL]` protetores — **sem** unpacker aberto confiável; abordagem é devirtualização parcial + análise de IAT/OEP | ver c.4 | — |

**Fluxo canônico de unpack** (detalhado em [06-workflows.md](06-workflows.md)):
`DIE` → confirma packer → `x64dbg` → anti-anti-debug (`ScyllaHide`) → `DetectOEP` →
breakpoint no OEP → `DumpModule` → `Scylla` para IAT → valida no DIE de novo (deve
agora dizer "não empacotado") → **e o dump tem de rodar fora do debugger**, não só abrir no
Ghidra: `diagnose-load.mjs` (o loader aceita?), `reset-load-state.mjs` (estado de carga) e,
se houver o original em claro, `verify-dump.mjs` (byte a byte) — e sem original, o *modo fraco*
do mesmo script. Duas armadilhas medidas neste caminho, com evidência em
[../reports/unpack-iat-hardcase.md](../reports/unpack-iat-hardcase.md): **descritor de import
com passo errado** (se o passo não for 20 bytes, o loader lê o #0 e para — os outros módulos
nem carregam) e o breakpoint de **software** antes de o stub decriptar a seção. Esta segunda
deixou de ser só aviso: `--hw-break` (**breakpoint de hardware**, que não escreve na memória)
é o caminho padrão do driver, ele confere se o BP foi armado (DR0-DR3 = 4 por thread; o 5º o
x64dbg descarta em silêncio), e o dump passa a ser conferido mesmo sem original — ver
[06-workflows.md](06-workflows.md) Cenário 1 e [../reports/verification-2026-10-14.md](../reports/verification-2026-10-14.md) §9.

### c.2 Anti-debug / anti-VM / anti-tamper

| Ferramenta | Uso | Licença |
|---|---|---|
| **ScyllaHide** | esconder debugger (PEB, NtGlobalFlag, DRx, timing, exceptions) | `GPL-3.0` |
| **TitanHide** | esconde via driver (kernel-level) | `GPL-3.0` |
| **al-khaser** | *test suite* de detecção — rode para saber o que o alvo detecta | `GPL-3.0` |
| **pafish** | idem, anti-VM/anti-sandbox | `GPL-3.0` |
| **VBoxHardenedLoader / VM cloaking** | esconder a VM (registro, drivers, MAC, timing) | `GPL-3.0` |
| **frida `--realm` + hooks** | neutralizar checks em runtime (patch no retorno) | `LGPL` |

- **Quando usar:** o alvo termina sozinho, comporta-se diferente, ou "não faz nada" no debugger/VM.
- **Por quê:** ~80% dos "o binário não funciona" são anti-debug/anti-VM, não bug da sua análise.

### c.3 Obfuscadores de código (MBA, control flow, string)

| Ferramenta | O que faz | Uso | Licença |
|---|---|---|---|
| **D-810** | plugin IDA que **desfaz ofuscação OLLVM** (flattening, MBA, substituições) | rodar no IDA; o equivalente Ghidra é script próprio | `MIT` |
| **msynth** | simplifica expressões **MBA** (mixed boolean-arithmetic) via síntese | `$ msynth -e "(a&b)+(a|b)"` | `BSD-3` |
| **Miasm** | framework IR + **desofuscação simbólica** + emulação | Python: `miasm.expression.simplification` | `GPL-2.0` |
| **Triton** | AST simbólica + simplificação de expressão | Python API | `Apache-2.0` |
| **HexRaysDeob** | plugin IDA para remover flattening OLLVM | IDA | `MIT` |
| **ollvm-breaker / de-flattening scripts** | scripts Ghidra comunitários | Ghidra script dir | variada |
| **Hikari / Tigress** | *geradores* de ofuscação — use para **criar casos de teste** do seu desofuscador | CLI | `BSD-3` / `[COMERCIAL]` |
| **ollvm** (LLVM pass) | idem, para gerar binários ofuscados de teste | build LLVM | `NCSA` |

- **Como usar (fluxo):** `DIE`/heurística de CFG detecta flattening → script Ghidra
  (`SimplifyControlFlow.java`) ou D-810 no IDA → msynth/Triton nas expressões MBA →
  re-analisa.
- **Por quê:** OLLVM é *o* obfuscador de software comercial moderno; sem desofuscar, o pseudocódigo é ilegível.

### c.4 Code virtualization (devirtualização)

| Ferramenta | O que faz | Licença |
|---|---|---|
| **VTIL** | IR de baixo nível + **lifters** para x86/x64; base para devirtualização | `BSD-3` |
| **NoVmp** | devirtualizador **VMProtect** (x64) — referência histórica, ainda útil como estudo | `GPL-3.0` |
| **VMHunt** | identifica regiões de VM em binários ofuscados | `GPL-3.0` |
| **Triton/angr + tracing** | abordagem geral: gravar trace da VM, reconstruir a semântica | `Apache-2.0` / `BSD-2` |

- **Quando usar:** o alvo tem uma "VM" de bytecode custom (VMProtect, tigress `--virtualize`).
- **Realismo:** devirtualização **completa** é pesquisa de meses. Na prática:
  trace TTD → identificar o dispatcher → reconstruir a semântica das handlers → reimplementar.
- **Por quê:** é o teto de dificuldade; saber que existe e como começar evita becos sem saída.

### c.5 .NET / Java / JS obfuscation

| Ferramenta | O que faz | Licença |
|---|---|---|
| **de4dot-cex** | deobfusca .NET (ConfuserEx, SmartAssembly, Eazfuscator…) | `MIT` |
| **NETReactorSlayer** | deobfusca especificamente .NET Reactor | `GPL-3.0` |
| **dnlib / Mono.Cecil** | ler/escrever IL programaticamente | `MIT` |
| **ConfuserEx** | *gerador* de ofuscação .NET (para criar testes) | `MIT` |
| **jadx** | descompila DEX/APK para Java (e deobfusca nomes comuns) | `Apache-2.0` |
| **Procyon / CFR / vineflower** | descompiladores Java bytecode (melhores que javap em lógica) | `Apache-2.0`/`MIT` |
| **wakaru** | deobfuscação de JS (submódulo do REA) | `MIT` |
| **js-beautify / deobfuscator.io** | formatação e desofuscação de JS | `MIT` |

### c.6 DRM e license checks

| Ferramenta | O que faz | Licença |
|---|---|---|
| **x64dbg + MCP** | inspecionar/patchear o check em runtime (breakpoint no `MessageBox`, no branch de erro) | `GPL-3.0` |
| **angr / Triton** | resolver o serial sem força bruta | `BSD-2` / `Apache-2.0` |
| **LIEF** | patchar o branch (jump condicional → NOP) de forma reprodutível | `Apache-2.0` |
| **Ghidra + pseudocódigo** | documentar o algoritmo do check (para interoperabilidade) | `Apache-2.0` |
| **VMProtect/Themida** | `[COMERCIAL]` — se o alvo usa, o check está virtualizado; ver c.4 | — |

> **Nota de escopo.** Analisar um check é legítimo (interoperabilidade, pesquisa). O
> que que **não** é legítimo é distribuir um bypass pronto para software de terceiros.
> Mantenha achados de proteção em `work/<alvo>/notes/` (fora do Git) e publique
> apenas *metodologia*, nunca contramedida específica de produto alheio.

---

## 5. Domínio (d) — Formatos e plataformas

### d.1 PE / PE+ (Windows) `✅ parcial (Ghidra + x64dbg)`

| Ferramenta | O que faz | Licença |
|---|---|---|
| **pefile** (Python) | parse programático completo de PE: seções, imports, exports, resources, TLS, debug | `MIT` |
| **LIEF** | parse + **reescrita** de PE | `Apache-2.0` |
| **pestudio** | `[FREEMIUM]` — GUI de triagem PE (imports, strings, entropia, indicadores) | — |
| **CFF Explorer / PE-bear** | inspeção/edição visual de PE | `MIT` (PE-bear) |
| **Ghidra + PDB** | símbolos públicos Microsoft (`msdl` no Ghidra) para nomear APIs | `Apache-2.0` |
| **PDB downloader** | baixar símbolos de qualquer módulo | `MIT` |

- **Quando usar:** triagem PE, reconstruir imports após unpack, extrair resources (ícones, manifests, versão).
- **Como usar:** `python -c "import pefile;pe=pefile.PE('t.exe');print([s.Name for s in pe.sections])"`

### d.2 ELF (Linux) `⬜` — via WSL

| Ferramenta | O que faz | Licença |
|---|---|---|
| **readelf / objdump / nm** | headers, seções, símbolos, desassembly (binutils) | `GPL-3.0` |
| **pyelftools** | parse ELF programático (símbolos, DWARF, notes) | `Unlicense` |
| **LIEF** | parse + reescrita ELF | `Apache-2.0` |
| **patchelf** | alterar interpreter/RPATH/`DT_NEEDED` de ELF | `GPL-3.0` |
| **Ghidra / radare2 / rizin** | análise e pseudocódigo | `Apache-2.0` / `LGPL` |
| **gdb + gef/pwndbg** | debug | `GPL-3.0` |
| **DWARF tools (dwarfdump, pahole)** | reconstruir structs de binários com debug info | `GPL` |

- **Quando usar:** qualquer alvo Linux. Se tem DWARF não-stripped, você tem quase o código-fonte.
- **Como usar:** `$ readelf -a target` · `$ pyelftools` · `$ ghidra headless`.

### d.3 Mach-O (macOS/iOS) `⬜`

| Ferramenta | O que faz | Licença |
|---|---|---|
| **LIEF** | parse + reescrita Mach-O (fat/universal) | `Apache-2.0` |
| **otool / nm / codesign** | inspeção nativa (Xcode CLT) | `[COMERCIAL]` (grátis) |
| **class-dump / dsdump** | extrai headers Objective-C de binários | `MIT` |
| **Hopper** | `[COMERCIAL]` — descompilador macOS/iOS muito bom | — |
| **Ghidra / radare2** | análise estática multi-arch (ARM64, x64) | `Apache-2.0` / `LGPL` |
| **Frida** | hooking em iOS/macOS | `LGPL` |

- **Quando usar:** apps macOS/iOS. No host Windows, análise estática de Mach-O funciona (Ghidra/r2/LIEF); *execução* não.
- **Nota:** o REA tem bridge `hopper` (precisa do Hopper instalado).

### d.4 APK / DEX / Android `⬜` (parcial via submódulo do REA)

| Ferramenta | O que faz | Licença |
|---|---|---|
| **apktool** | decode/rebuild de APK: resources, smali, manifest | `Apache-2.0` |
| **jadx** (+ `jadx-headless-mcp`) | descompila DEX → Java legível | `Apache-2.0` |
| **baksmali/smali** | montar/desmontar bytecode Dalvik | `BSD-3` |
| **dex2jar / d2j-dex2jar** | DEX → JAR (para o Java decompiler) | `Apache-2.0` |
| **Frida (+ `frida-server`)** | hooking em app Android (unpinning, dump de chaves) | `LGPL` |
| **objection** | toolkit sobre Frida para Android/iOS (bypass de root/SSL pinning) | `MIT` |
| **MobSF** | `[FREEMIUM]` — análise automatizada de APK (estática+dinâmica) | `GPL-3.0` |
| **ADB / `adb`** | comunicação com device/emulador | `Apache-2.0` |
| **emulador (AVD / Genymotion)** | ambiente de execução Android | `Apache-2.0` / `[COMERCIAL]` |
| **Ghidra** | análise de `.so` nativos (ARM/ARM64) | `Apache-2.0` |
| **Il2CppDumper + Il2CppInspector** | reverter jogos/apps Unity IL2CPP (`global-metadata.dat`) | `MIT` |

- **Quando usar:** qualquer app Android. Fluxo: `jadx` (Java) → `.so` nativo no Ghidra → Frida em runtime.
- **Por quê:** o REA já traz `jadx-headless-mcp` como submódulo — inicialize-o (G2) em vez de reinstalar.

### d.5 Firmware / IoT / embedded `⬜`

| Ferramenta | O que faz | Licença |
|---|---|---|
| **binwalk** | identifica e **extrai** assinaturas em firmware (squashfs, cramfs, kernels) | `MIT` |
| **unblob** | extractor moderno (substitui binwalk em muitos casos), extração em cadeia | `MIT` |
| **UEFITool** | parse/extração de **UEFI/BIOS** (módulos PEI/DXE) | `BSD-2` |
| **fmk / FACT** | framework de análise de firmware | `GPL` |
| **Qiling / Unicorn** | emular firmware (MIPS/ARM) sem hardware | `GPL-2.0` |
| **sasquatch / unsquashfs** | extrair SquashFS (com patches p/ variantes) | `GPL-2.0` |
| **Ghidra** | análise de firmware (MIPS/ARM/PPC/AVR/8051) | `Apache-2.0` |
| **firmware-mod-kit** | rebuild de firmware | `GPL-2.0` |
| **`extract-firmware` (scripts próprios)** | pipeline binwalk→unblob→recursivo | `MIT` |

- **Quando usar:** roteadores, câmeras, dispositivos IoT. Fluxo: `binwalk -e` → `unblob` no que sobrou → identificar FS → `sasquatch` → análise.
- **Por quê:** firmware é 60% do "software comercial embarcado" e tem um fluxo próprio.

### d.6 .NET / IL e Java bytecode `⬜`

| Ferramenta | O que faz | Licença |
|---|---|---|
| **dnSpyEx** | debugger + decompilador .NET (edita e recompila) | `GPL-3.0` |
| **ILSpy + ilspycmd** | decompilador .NET, CLI para automação | `MIT` |
| **dnlib** | ler/escrever IL | `MIT` |
| **de4dot-cex** | deobfuscar .NET | `MIT` |
| **dotnet SDK / ILAsm** | montar IL, buildar | `MIT` |
| **CFR / Procyon / vineflower** | descompilar Java bytecode | `Apache-2.0` / `MIT` |
| **jd-cli** | wrapper CLI do Java decompiler | `MIT` |

- **Quando usar:** alvos gerenciados — .NET e Java são *os mais fáceis*: o IL/bytecode é semi-fonte.
- **Como usar:** `$ ilspycmd -p -o out/ target.dll` · `$ de4dot-cex target.exe`

### d.7 WebAssembly `⬜`

| Ferramenta | O que faz | Licença |
|---|---|---|
| **wabt** (`wasm2wat`, `wasm-decompile`, `wasm-objdump`) | desmontar/descompilar WASM para WAT | `Apache-2.0` |
| **wasm-decompile** (parte do wabt) | pseudo-C legível | `Apache-2.0` |
| **binaryen** (`wasm-dis`, `wasm-opt`) | IR de WASM + otimização/desofuscação | `Apache-2.0` |
| **Ghidra (wasm plugin)** | análise no Ghidra | `Apache-2.0` |
| **wakaru** | desofuscação/limpeza (submódulo do REA) | `MIT` |

- **Quando usar:** apps web modernos que compilam para WASM (jogos, editores, CAD no browser).
- **Como usar:** `$ wasm-decompile module.wasm -o module.dcmp` · `$ wasm2wat module.wasm`
- **Nota:** o REA já traz `wabt` e `wakaru` como submódulos (G2).

### d.8 EVM / blockchain bytecode `⬜`

| Ferramenta | O que faz | Licença |
|---|---|---|
| **evmole** | extrai assinaturas/selectors de bytecode EVM (submódulo do REA) | `MIT` |
| **panoramix / heimdall** | descompilador EVM | `LGPL` |
| **cast (Foundry)** | inspeção/desassemblagem EVM | `MIT` |

- **Quando usar:** contratos inteligentes, análise de bytecode on-chain.
- **Nota:** o REA já cobre EVM (`docs/evm-bytecode.md`).

### d.9 Go e Rust (recuperação de símbolos) `⬜`

| Ferramenta | O que faz | Licença |
|---|---|---|
| **GoReSym / redress** | recupera nomes de funções Go de binários stripped | `MIT` |
| **Go pclntab parsers** | idem, programático | `MIT` |
| **Ghidra golang analyzer** | aplica nomes no Ghidra | `Apache-2.0` |
| **rust-demangler / rustfilt** | demangle de símbolos Rust | `MIT`/`Apache-2.0` |

- **Quando usar:** binários Go/Rust (cada vez mais comuns) — ambos são *muito* diferentes de C/C++ na análise.
- **Por quê:** sem recuperar símbolos, um binário Go é uma parede de `sub_401000`.

---
## 6. Domínio (e) — Reconstrução e patching

| Ferramenta | O que faz | Quando usar | Como usar | Licença |
|---|---|---|---|---|
| **Scylla** | reconstrução de IAT | pós-unpack | plugin x64dbg | `GPL-3.0` |
| **PE-sieve** | dump de processo/regiões | extrair código desempacotado da memória | `pe-sieve64 /pid N /dir out` | `BSD-2` |
| **x64dbg `DumpModule`** (MCP) | dump de módulo em memória | idem, via IA | tool `DumpModule` | `GPL-3.0` |
| **LIEF** | patch programático (seções, imports, EP) | patching reprodutível | API Python | `Apache-2.0` |
| **Keystone** | montar instrução e injetar | patch de bytes | API Python | `BSD-3` |
| **CFF Explorer / PE-bear** | patch visual de PE | ajuste pontual | GUI | `MIT` |
| **Ghidra pseudocódigo** | "código limpo" para portar | reimplementação | GUI/headless | `Apache-2.0` |
| **RetDec** | decompilador alternativo (melhor em alguns casos) | segunda opinião de pseudocódigo | `$ retdec-decompiler t.exe` | `MIT` |
| **rev.ng** | decompilador + **recompilação** (`revng translate`) | quando você quer *recompilar* um binário | `[FREEMIUM]` | — |
| **ghidriff / Diaphora** | bindiff | "o que mudou?" | `ghidriff old new` | `Apache-2.0`/`GPL-3.0` |
| **bincat** | lifting binário→IR para recompilação | pesquisa avançada | `MIT` | — |

**Fluxo de reconstrução:** pseudocódigo (Ghidra) → normalizar nomes/tipos → extrair
algoritmos com evidência (trace do x64dbg/TTD confirma cada ramo) → **especificação
comportamental** em `reports/<alvo>-spec.md` → implementação própria.

- **Por quê separar spec de código:** a spec é o que você publica/documenta; o código
  novo é seu. Sem a spec, você "reescreve de memória" e erra detalhes.

---

## 7. Domínio (f) — Automação e scripting

### f.1 Scripts Ghidra

| Recurso | Uso | Licença |
|---|---|---|
| **Java scripts** (`*.java`) | acesso total à API do Ghidra; colocar em `work/<alvo>/scripts/` | `Apache-2.0` |
| **PyGhidra** (Python 3) | rodar Ghidra de dentro de Python 3 (`pip install pyghidra`) | `Apache-2.0` |
| **Jython** (Python 2) | scripts legados (maioria dos repos públicos) | `PSF` |
| **Ghidra headless + `-postScript`** | automação em lote | `Apache-2.0` |

```java
// work/<alvo>/scripts/ExportPseudocode.java — esqueleto
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
public class ExportPseudocode extends GhidraScript {
  public void run() throws Exception {
    DecompInterface d = new DecompInterface(); d.openProgram(currentProgram);
    for (var f : currentProgram.getFunctionManager().getFunctions(true)) {
      var res = d.decompileFunction(f, 60, monitor);
      println("// " + f.getName() + "\n" + res.getDecompiledFunction().getC());
    }
  }
}
```

### f.2 Scripts x64dbg

| Recurso | Uso |
|---|---|
| **script engine** | `headless.exe -a script.txt` para automação sem GUI |
| **`_scriptapi`** (C++) | plugin com acesso programático (base do x64dbg-MCP) |
| **MCP `ExecuteDebuggerCommand`** | rodar qualquer comando x64dbg via IA |

```text
// work/<alvo>/scripts/break-and-dump.txt
bp kernel32.CreateFileW
run
log "CreateFileW chamada: {arg1}"
StepOut
dump module, work/<alvo>/unpacked/dumped.exe
```

### f.3 Pipelines e orquestração

| Ferramenta | O que faz | Licença |
|---|---|---|
| **`just` / `make`** | runner de tarefas do projeto (`just triage <alvo>`) | `CC0` / `GPL` |
| **Python + `uv`** | ambiente Python reprodutível para scripts | `MIT`/`Apache-2.0` |
| **`rich`/`typer`** | CLIs legíveis | `MIT` |
| **REA** | orquestrador de alto nível com evidência | `MIT` |

### f.4 Integração com LLM

| Peça | O que faz | Licença |
|---|---|---|
| **x64dbg-MCP** | debug controlado por IA (HTTP + token) | `MIT` |
| **GhidraMCP / ghidra-mcp** | expõe o Ghidra via MCP (decompile, rename, xrefs) | `Apache-2.0` |
| **IDA Pro MCP** | expõe o IDA via MCP | `MIT` |
| **REA MCP** | orquestração + evidência | `MIT` |
| **cliente MCP** (Claude Code, Codex, Cursor, OpenCode, Gemini CLI, VS Code) | o LLM que consome | variada |

Ver [05-mcp.md](05-mcp.md) para a matriz completa e a ordem de subida.

---
## 8. Domínio (g) — Rede e protocolo

| Ferramenta | O que faz | Quando usar | Como usar | Licença |
|---|---|---|---|---|
| **Wireshark + tshark** | captura e dissecção de tráfego | ver o que o alvo fala na rede | `tshark -i any -w cap.pcapng` · `tshark -r cap -Y http` | `GPL-2.0` |
| **mitmproxy** | proxy HTTP/HTTPS interativo + scriptável | reverter API HTTP; alterar respostas | `mitmproxy -p 8080 -s addon.py` | `MIT` |
| **mitmproxy2swagger** | gera OpenAPI a partir de um HAR | documentar protocolo REST | `$ mitmproxy2swagger -i cap.har` | `MIT` |
| **Burp Suite** | `[FREEMIUM]` — proxy + scanner | testes web/API avançados | GUI | — |
| **Kaitai Struct** | linguagem para descrever **formato binário**; gera parser | protocolo binário proprietário | `ksc -t python proto.ksy` | `MIT` |
| **Scapy** | construir/parsear pacotes, fuzzing de rede | protocolos L2–L7 custom | Python API | `GPL-2.0` |
| **boofuzz** | fuzzing de protocolos (sucessor do Sulley) | achar bugs em protocolo | Python API | `GPL-2.0` |
| **Frida (unpinning)** | neutralizar certificate pinning | app com pinning bloqueia o mitmproxy | `frida -l unpin.js` | `LGPL` |
| **objection** | unpinning/root-bypass Android/iOS | mobile | `objection -g app explore` | `MIT` |
| **HTTP Toolkit** | `[FREEMIUM]` — interceptação fácil | análise rápida de API | GUI | — |
| **SSLKEYLOGFILE** | descriptografar TLS com as chaves do app | quando o app loga as chaves | env `SSLKEYLOGFILE` | — |

- **Fluxo canônico:** Procmon/TCPView (o alvo fala com quem?) → tshark (o que trafega) →
  mitmproxy (se HTTP, decifrar e mapear) → Kaitai (se binário, descrever o formato) →
  boofuzz (se for testar robustez).
- **Por quê:** metade da "lógica de negócio" de software comercial vive no servidor —
  reverter o protocolo às vezes é mais rápido que reverter o cliente.

---

## 9. Camada transversal — Isolamento e laboratório

Executar alvo desconhecido no host é **irreversível**. Esta camada não é opcional.

| Ferramenta | O que faz | Licença |
|---|---|---|
| **Windows Sandbox** | container Windows efêmero, descartável por natureza | `[COMERCIAL]` (grátis em Pro/Ent) |
| **VMware / VirtualBox / Hyper-V** | VM com **snapshot** (reverter após cada amostra) | `[FREEMIUM]` / `GPL-2.0` / `[COMERCIAL]` |
| **FLARE VM** | distribuição Windows pré-carregada com ferramentas de RE | `MIT` (scripts) |
| **REMnux** | distribuição Linux para análise de malware/rede | `GPL` |
| **Docker/Podman** | isolamento de processos de análise (não de kernel) | `Apache-2.0` |
| **WSL2** | laboratório Linux leve | `[COMERCIAL]` (grátis) |
| **`snapshot-reset.ps1`** | reverte a VM entre amostras | próprio (`MIT`) |

- **Regra:** amostra desconhecida → **sempre** em VM com snapshot, rede restrita,
  sem credenciais reais, sem compartilhamento de pasta do host.

---
## 10. Cobertura — checklist contra o pedido original

| Domínio pedido | Sub-item | Ferramenta primária | Coberto? |
|---|---|---|---|
| a) Estática | Descompilação x86/x64/ARM/MIPS/RISC-V | Ghidra (+RetDec, r2) | ✅ |
| a) Estática | CFG, call graph, data flow | Ghidra, r2 | ✅ |
| a) Estática | Detecção de compilador/linguagem | DIE, Ghidra, GoReSym | ✅ |
| a) Estática | Símbolos, strings, imports/exports | pefile, pyelftools, LIEF, r2 | ✅ |
| a) Estática | Bindiff | ghidriff, Diaphora | ✅ |
| a) Estática | Execução simbólica | angr, Triton | ✅ |
| b) Dinâmica | Debug usermode | x64dbg (+MCP), GDB, LLDB | ✅ |
| b) Dinâmica | Debug kernel | WinDbg | ✅ |
| b) Dinâmica | Tracing (instr/syscall/API) | DynamoRIO, TinyInst, Frida, TTD, ETW | ✅ |
| b) Dinâmica | Hooking / DBI | Frida, DynamoRIO, TinyInst | ✅ |
| b) Dinâmica | Emulação | Unicorn, Qiling, Speakeasy | ✅ |
| c) Desobfuscação | Packers | UPX, Scylla, x64dbg, DIE | ✅ |
| c) Desobfuscação | Obfuscadores LLVM/.NET | D-810, msynth, de4dot, NETReactorSlayer | ✅ |
| c) Desobfuscação | Anti-debug/VM/tamper | ScyllaHide, TitanHide, al-khaser, pafish | ✅ |
| c) Desobfuscação | Code virtualization | VTIL, NoVmp, VMHunt, Triton+TTD | ✅ |
| c) Desobfuscação | DRM / license checks | x64dbg, angr, LIEF | ✅ |
| c) Desobfuscação | Integrity/checksum | x64dbg + LIEF (patch e valida) | ✅ |
| d) Formatos | PE/PE+ | pefile, LIEF, PE-bear | ✅ |
| d) Formatos | ELF | pyelftools, readelf, LIEF | ✅ |
| d) Formatos | Mach-O | LIEF, class-dump, Hopper | ✅ |
| d) Formatos | APK/DEX | apktool, jadx, Frida, Il2CppDumper | ✅ |
| d) Formatos | Firmware | binwalk, unblob, UEFITool, Qiling | ✅ |
| d) Formatos | .NET/IL, Java | dnSpyEx, ILSpy, de4dot, CFR | ✅ |
| d) Formatos | WebAssembly | wabt, binaryen, wakaru | ✅ |
| d) Formatos | EVM | evmole, heimdall | ✅ |
| d) Formatos | Go/Rust | GoReSym, redress, rustfilt | ✅ |
| e) Reconstrução | Reconstrução de IAT | Scylla | ✅ |
| e) Reconstrução | Dump de processo | PE-sieve, x64dbg DumpModule | ✅ |
| e) Reconstrução | Patching / recompilação | LIEF, Keystone, rev.ng | ✅ |
| e) Reconstrução | Pseudocódigo limpo | Ghidra, RetDec | ✅ |
| e) Reconstrução | Diff de binários | ghidriff, Diaphora | ✅ |
| f) Automação | Scripts Ghidra | Java, PyGhidra, Jython | ✅ |
| f) Automação | Scripts x64dbg | script engine, `_scriptapi` | ✅ |
| f) Automação | Pipelines | `just`, Python/uv, REA | ✅ |
| f) Automação | Integração LLM | x64dbg-MCP, GhidraMCP, REA MCP | ✅ |
| g) Rede | Captura/análise | Wireshark, tshark | ✅ |
| g) Rede | Reversão de protocolo | mitmproxy, Kaitai, Scapy | ✅ |
| g) Rede | SSL/TLS interception | mitmproxy, Frida unpinning | ✅ |
| g) Rede | Fuzzing de protocolo | boofuzz, AFL++ (WSL) | ✅ |

**Nenhum gap declarado.** O que resta é *profundidade* (devirtualização total é
pesquisa, não instalação) e *licença* (Hopper/Burp/IDA são comerciais — marcados).

---

## 11. Resumo de instalação por perfil

| Perfil (`bootstrap-windows.ps1 -Profile`) | Ferramentas |
|---|---|
| `core` | corrige REA (npm ci + build + submódulos), compila x64dbg-MCP (Zig), cria `plugins/`, instala Jython+PyGhidra |
| `static` | radare2/rizin, LIEF, capstone/keystone, YARA/yara-x, DIE, ghidriff, ImHex, RetDec, angr/Triton |
| `dynamic` | Frida, DynamoRIO/TinyInst, WinDbg+TTD, ScyllaHide, TitanHide, PE-sieve/HollowsHunter, Moneta, Sysinternals, al-khaser |
| `formats` | apktool, jadx, d2j-dex2jar, baksmali, Il2CppDumper, dnSpyEx/ILSpy/ilspycmd, de4dot, wabt/binaryen, binwalk/unblob/UEFITool, GoReSym, CFR |
| `network` | Wireshark/tshark, mitmproxy + mitmproxy2swagger, Kaitai, Scapy, boofuzz, objection |
| `wsl` | Ubuntu 24.04 + binutils, pyelftools, patchelf, gdb+gef/pwndbg, AFL++, angr, Qiling, qemu, sasquatch, fmk |
| `full` | todos os anteriores |

Cada perfil é idempotente e termina com um `health-check` verde naquele escopo.

# UnboxRE — a reverse-engineering toolkit built to be operated by an AI agent

UnboxRE turns a fresh Windows machine into a working reverse-engineering bench **and** gives an
LLM agent a documented, evidence-first way to drive it: static triage without a debugger, live
in-process instrumentation, dump reconstruction, and MCP bridges to Ghidra and x64dbg. It never
redistributes third-party tools — it fetches them from upstream, declares every license in
[`config/`](config/) and keeps each analyzed sample out of Git.

> **Language note.** This README is the English entry point. The deep documentation in `docs/**`
> — and every tool's console output — is written in **Brazilian Portuguese** on purpose: that is
> the language of the analysis reports this toolkit exists to produce. It is not an oversight;
> it is the one place where this repository is intentionally bilingual.

---

## 1. What it is

| Piece | Role |
|---|---|
| **Toolkit scripts** ([scripts/](scripts/README.md)) | Dependency-free Node/Python/PowerShell tools for the first questions of any analysis: *is it packed?*, *what runs before `main`?*, *why won't it load?*, *what is at this address?*, *what is inside this container / this JAR?* |
| **Documentation** ([docs/](docs/)) | Numbered guides: architecture and artifact contract, tool catalog, licenses, install, MCP, step-by-step workflows, AI operating contract, hygiene |
| **Reports** ([reports/](reports/)) | Measured evidence: every claim in a report comes from a command the author actually ran, and what failed is in its own section |
| **Config** ([config/](config/)) | Tool manifest (`tools.json`), verified license registry (`licenses.json`), MCP templates, environment example |
| **Work area** (`work/<target>/`) | Per-case workspace: target copy + hash, unpacked artifacts, notes, captures, evidence — **Git-ignored, never published** |
| **MCP bridges** | REA (orchestration + evidence contract, 170 tools) over stdio, and the x64dbg plugin over HTTP — see [docs/05-mcp.md](docs/05-mcp.md) |

```
                    ┌──────────────────── LLM / Agent ────────────────────┐
                    │  Claude Code · Codex · Cursor · OpenCode · Gemini …  │
                    └───────┬──────────────┬───────────────┬───────────────┘
                            │ MCP (stdio)  │ MCP (HTTP)    │ MCP (stdio)
                    ┌───────▼───────┐ ┌────▼──────────┐ ┌──▼────────────┐
                    │  REA (bridge) │ │ x64dbg-MCP    │ │ r2 / IDA /    │
                    │  ghidra/ida/  │ │ (in-process   │ │ GhidraMCP …   │
                    │  jeb/hopper   │ │  inside x64dbg)│ │              │
                    └───────┬───────┘ └────┬──────────┘ └──┬────────────┘
                            │              │               │
              ┌─────────────▼──┐   ┌───────▼───────┐  ┌────▼─────────────┐
              │ Ghidra         │   │ x64dbg        │  │ radare2 / IDA    │
              │ + JDK          │   │ + plugins     │  │ Free / JEB       │
              │ (static)       │   │ (dynamic)     │  │ (static)         │
              └────────────────┘   └───────────────┘  └──────────────────┘
```

## 2. Scope and status

**Validated scope: Windows 10/11 (x64).** That is where the critical path — PE/PE+, .NET/IL, live
processes, the Ghidra/x64dbg GUIs, MCP servers — has been exercised end to end. Linux/WSL and
macOS are **roadmap, not supported**: the hooks that exist for them (`bootstrap-wsl.sh`, the
Linux branch of `fetch-tools.sh`) are courtesy, not a promise. This is also the standing rule in
[AGENTS.md](AGENTS.md): do not describe as "working" what was not exercised.

The toolkit's own readers (triage, disassembly, byte reading, container/JVM inspection) *do*
understand **ELF**, **archives** and **JVM bytecode**, because six real targets forced each of
them in — see [the sequence report](reports/sequencia-nivel-1-a-6.5.md).

## 3. Requirements

| Requirement | Why |
|---|---|
| Windows 10/11 x64 | the validated host |
| PowerShell 5.1+ | the `.ps1` half of the toolkit (the Windows-shipped version is enough) |
| Node.js 18+ | the `.mjs` scripts; they use **no npm packages** (CI runs Node 22; Node 24 tested locally) |
| Python 3.10+ | `scripts/disasm-range.py` only; it needs `capstone` (installed by the `static` bootstrap profile; tested locally with Python 3.11 + capstone 5.0.7) |
| Git | fetching the third-party core and cloning cases |
| Network | only for `fetch-tools -Apply` / `bootstrap -Apply` |
| Administrator rights | **never requested by the toolkit itself.** If an installer needs elevation it asks for it; the scripts do not elevate on their own |

## 4. Quick start (clean clone → working bench)

```powershell
# 0) Read-only health check of the machine (installs nothing)
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\health-check.ps1 -Json

# 1) Fetch the third-party core from upstream — dry-run first, then apply.
#    (Ghidra, x64dbg, REA and the x64dbg-MCP plugin are NOT vendored: a clean clone lacks them.)
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\fetch-tools.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\fetch-tools.ps1 -Apply

# 2) Toolchain by profile — ALSO dry-run first: nothing is installed without -Apply
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1 -Profile core -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1 -Profile core -Apply

# 3) Prove the AI bridge is alive (real MCP handshake over stdio)
node .\scripts\smoke-mcp.mjs

# 4) Generate MCP config for your client (writes nothing without --apply)
node .\scripts\gen-mcp-config.mjs --client claude-desktop --check
node .\scripts\gen-mcp-config.mjs --client claude-desktop --apply

# 5) Re-check the machine
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\health-check.ps1
```

Profiles: `fetch`, `core`, `static`, `dynamic`, `mobile`, `firmware`, `net`, `plugins`, `wsl`,
`all` (plus the historical aliases `formats`, `network`, `full`). `core` already runs `fetch`
first, so step 2 alone covers steps 1–2. Clients for `gen-mcp-config`: `claude-desktop`,
`claude-code`, `cursor`, `windsurf`, `gemini`, `vscode`, `codex` — run
`node scripts/gen-mcp-config.mjs --list` to see them all with their config paths. In Git Bash the
equivalents are `bash scripts/health-check.sh` and `bash scripts/fetch-tools.sh`.

**Verified on this machine, on 2026-10-15** (trimmed to the first lines; `-Json` reproduces the
whole report, one object per check):

```console
$ powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\health-check.ps1 -Json
{
    "generatedAt":  "2026-10-15T12:29:50.0124697-03:00",
    "root":  "C:\Users\Admin\Desktop\UnboxRE",
    "summary":  {
                    "ok":  41,
                    "warn":  0,
                    "fail":  0
                },
    "results":  [
                    {
                        "Check":  "layout:docs",
                        "Level":  "OK",

$ node .\scripts\smoke-mcp.mjs

UnboxRE — smoke test do MCP (stdio)
  entrada: C:\Users\Admin\Desktop\UnboxRE\rea-main\scripts\rea.mjs
  initialize → serverInfo: {"name":"rea","version":"6.4.0"}
  tools/list  → 170 ferramentas (ex.: annotate_native_function, inspect_native_load_image, inspect_native_data_type)

  [OK] a ponte MCP sobe e responde a uma chamada real.
```

## 5. Repository layout

```
scripts/     the toolkit itself (one purpose per file); full map in scripts/README.md
docs/        00 diagnose · 01 architecture · 02 tool catalog · 03 licenses · 04 install
             05 MCP · 06 workflows (12 scenarios) · 07 AI operating contract
             08 hygiene/security · tools/ one datasheet per core tool
reports/     measured evidence per round + the six-target sequence summary
config/      tools.json · licenses.json · mcp/ templates · env/ example
work/<target>/   per-case workspace (Git-ignored): src/ unpacked/ notes/ scripts/
                 captures/ evidence/ — created by scripts/new-case.ps1
ghidra/ x64dbg/ rea-main/ .cache/   third-party core + cache — Git-ignored, fetched from upstream
```

Case workflow and the artifact contract: [docs/01-arquitetura.md](docs/01-arquitetura.md) and
[docs/06-workflows.md](docs/06-workflows.md).

## 6. The toolkit in action (real runs, trimmed)

**a) Is it packed — and how strong is that evidence?** Run against a 31 MB native DLL pulled out
of a real protected JAR (the same one used in example *c*):

```console
$ node scripts/identify-protections.mjs x64-windows.dll
  tamanho: 31453712 bytes · arq: x64 · entrypoint: 0x28be058
  seções:
               virt=7237023  raw=2325504  entropia=7.99 -X
               virt=3609766  raw=2358272  entropia=7.98 --
               ...
    .upx1      virt=9216000  raw=0        entropia=0 WX
    .boot      virt=5317632  raw=5317632  entropia=7.95 -X
    .reloc     virt=4096     raw=16       entropia=2.73 --
  [? ] Nome de seção UPX sem marcador UPX! (medium) — seção(ões) .upx1 e nenhum "UPX!" no arquivo…
  [? ] Entry point fora de .text (medium) — entrypoint cai em ".boot"
  [? ] Alta entropia (low) — seções com entropia >= 7.2: ...
  [? ] Seções virtuais sem dados no arquivo (medium) — .upx1
  Veredito: possivelmente incomum
```

Note how evidence strength is separated: a real `UPX!` marker is a **high** finding; a section
*named* `.upx1` with no marker anywhere is only **medium**, because the name is imitable — a
protector can reuse it to mislead. Before that fix the verdict came out "PROVAVELMENTE PROTEGIDO"
from the name alone (measured, and corrected in
[round 8.6, §5.1](reports/round-8-6-nivel-6.5.md#51-falso-positivo-de-upx-nome-de-seção-tratado-como-assinatura)).

**b) What is actually at this address?** The step between "the disassembly says `rva 0x28be000`"
and reading the bytes there — here, the entry stub of that packed DLL:

```console
$ node scripts/pe-read.mjs x64-windows.dll --rva 0x28be000 --len 24 --as hex
  rva 0x28be000 · 24 byte(s) · seção .boot (R-X, offset no arquivo 0x18ece00)

  off 0x18ece00  rva 0x28be000  d8 49 a5 36 e8 fa 75 c5 cf 68 67 2e 8f f6 dd 14  .I.6..u..hg.....
  off 0x18ece10  rva 0x28be010  53 53 bd 62 1b 7c 92 8e                          SS.b.|..
```

With no `--rva`/`--off`/`--section` it prints the section map (RVA ↔ file offset), which is what
turns an address from a report into a byte in the file:

```console
$ node scripts/pe-read.mjs x64-windows.dll
  31453712 bytes · PE · ImageBase=0x180000000
  seção        rva        offset     virt     raw      perms
               0x001000   0x000600   7237023  2325504  R-X
               0x6e8000   0x238200   3609766  2358272  R--
               ...
  .upx1        0x1ff4000  0x18ece00  9216000  0        RWX
  .boot        0x28be000  0x18ece00  5317632  5317632  R-X
```

**c) A JAR that hides a 31 MB native lock** — the triage finds it without opening the DLL:

```console
$ node scripts/triage-java.mjs Myau-COM-TRAVA.jar
  UnboxRE — triagem de Java: Myau-COM-TRAVA.jar
  32922330 bytes (31.40 MB) · JAR/ZIP · sha256 173CDD307965BF7E…
  entradas: 801 · classes: 722 (abertas: 722)
  binários nativos embutidos (a lógica pode estar aqui, não no bytecode):
    antiLeak-1a2786b1-7d43-4a96-b4bc-752eb89b1600/x64-windows.dll  31453712 bytes (30.00 MB)

  [!!] classes com método native: 33  (métodos nativos: 101; marcadores de 40 hex: 32)
    myau/JK  (8 nativo(s) · 1 marcador(es) 40-hex)
      z(Lnet/minecraft/util/BlockPos;JLnet/minecraft/util/EnumFacing;Lnet/minecraft/util/Vec3;)V, …
    …
  [!!] classe(s) que CARREGAM biblioteca nativa (o loader da trava):
    antiLeak-1a2786b1-7d43-4a96-b4bc-752eb89b1600/Loader  (…/Loader.class)
      chama: java/lang/System.load
      e extrai: java/io/File.mkdir, java/lang/Class.getResourceAsStream, java/io/FileOutputStream.<init>

  [!!] 88 par(es) de entradas que só diferem por MAIÚSCULA:
    myau/A.class  |  myau/a.class
    …
    extrair isto em NTFS sem pasta case-sensitive SOBRESCREVE um dos dois em silêncio
```

**d) Why does this `.exe` exit with `0xC000007B`?** Loader-state analysis plus the real exit
status, with no debugger in the loop:

```console
$ node scripts/diagnose-load.mjs sample.exe
$ node scripts/diagnose-load.mjs sample.exe --stdin "<candidate password>"   # feed a console target
```

The rest of the map — static triage with `--refs`/`--data-refs`, `disasm-range.py`,
`triage-archive.mjs`, live instrumentation with `park-patch-run.ps1`, dump reconstruction with
`rebuild-iat.mjs` / `reset-load-state.mjs` / `verify-dump.mjs`, and the x64dbg driver
`x64dbg-drive.mjs` — is described in [scripts/README.md](scripts/README.md) (purpose, flags and
what each one writes) and used recipe by recipe in
[docs/06-workflows.md](docs/06-workflows.md).

> `node scripts/<script>.mjs --help` and `python scripts/disasm-range.py --help` print usage and
> exit `0`. For the PowerShell scripts, read the comment header instead
> (`Get-Content scripts\new-case.ps1 -TotalCount 60`): on this host `Get-Help` cannot resolve
> comment-based help at all — measured, including against a minimal control script — and `-?`
> prints nothing. That limitation, and what to use instead, is documented in
> [scripts/README.md](scripts/README.md).

## 7. Driving it from an AI agent

Two bridges are documented in [docs/05-mcp.md](docs/05-mcp.md): the **REA** bridge (stdio, the
orchestrator that carries the evidence contract — 170 tools) and the **x64dbg-MCP** plugin (HTTP,
living inside a running debugger process). An agent can also call the toolkit scripts directly
through a shell, which is the cheapest path for triage questions.

The prompts below are written against tools that exist today — nothing aspirational. Paste them
into an agent that has the REA bridge; for the dynamic ones, the debugger must already be up
(`powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-x64dbg.ps1`, then
`node .\scripts\mcp-x64dbg-smoke.mjs` to prove the bridge answers).

**Static triage**

- "Triage this binary: is it packed, and with what? Tell me how strong each piece of evidence is
  and what to look at next."
- "What code in this sample runs **before** `main`? Show the TLS callbacks (on ELF, `DT_INIT` /
  `DT_INIT_ARRAY`) and what they do."
- "List the imports by module, and flag anything that looks like anti-debug or anti-VM."
- "Read the bytes at RVA `0x28be000` as `u32` and as a string, and tell me what that constant is
  used for."
- "Where is the string `'texto'` used in the code, and what does the code do right after it?"

**Containers and JVM**

- "Triage this archive: what is inside, what format is each member, and is there a native
  component in it?"
- "This is a JAR: which classes have `native` methods, is anything extracting and loading a
  shared library, and do the entry names collide by case?"
- "Which Python interpreter does this packaged target need? Find the ABI hint inside it."

**Dynamic (needs the x64dbg bridge)**

- "Load this sample in x64dbg, wait for the module, set a **hardware** breakpoint on the OEP, and
  dump the image to `unpacked/`."
- "This sample computes right after reading input and exits in under a millisecond — instrument
  it **before** feeding the input, and read back what it prepared."
- "This memory dump won't load: fix the loader state and rebuild the import table."

**Verification (the part that makes a report credible)**

- "Compare this dump against the original and classify every differing byte: loader-filled, load
  state, or an actual code/data difference worth investigating."
- "Before you report anything as done, run the offline consistency check and the license check,
  and show me their exit codes."

Agents must follow [docs/07-operacao-por-ia.md](docs/07-operacao-por-ia.md): what it may decide
alone, when it must stop and ask, and how to report evidence (command plus real output, with what
failed in its own section). The short version of the operating rules is [AGENTS.md](AGENTS.md).

## 8. Documentation

| Document | What it is for |
|---|---|
| [docs/00-diagnostico.md](docs/00-diagnostico.md) | Environment audit: what works, what is missing, root cause, risk |
| [docs/01-arquitetura.md](docs/01-arquitetura.md) | Directory structure, naming conventions, workflow, where each artifact lives |
| [docs/02-catalogo-ferramentas.md](docs/02-catalogo-ferramentas.md) | Exhaustive per-domain tool catalog, with "when to use", "how to use", integration and license |
| [docs/03-licencas.md](docs/03-licencas.md) | License matrix, MIT compatibility, what may and may not go to GitHub |
| [docs/04-instalacao.md](docs/04-instalacao.md) | Step-by-step install, per profile, with verification after each step |
| [docs/05-mcp.md](docs/05-mcp.md) | Every MCP server, variables, tokens, startup order, troubleshooting |
| [docs/06-workflows.md](docs/06-workflows.md) | The twelve step-by-step scenarios (target triage, unpacking, dumps, ELF, containers, JVM…) |
| [docs/07-operacao-por-ia.md](docs/07-operacao-por-ia.md) | The AI operating contract: autonomy, stop conditions, evidence format |
| [docs/08-higiene-e-seguranca.md](docs/08-higiene-e-seguranca.md) | Sample isolation, VM snapshots, network, chain of custody |
| [docs/tools/](docs/tools/README.md) | One datasheet per core tool (Ghidra, x64dbg, REA, x64dbg-MCP, radare2, LIEF, Frida…) |
| [scripts/README.md](scripts/README.md) | The script map: purpose, environment, whether it writes, flags |
| [reports/sequencia-nivel-1-a-6.5.md](reports/sequencia-nivel-1-a-6.5.md) | One page on the six-target sequence: what each demanded, what it added to the toolkit, what stayed open |

## 9. Results so far

Six real targets, each treated as a test of the toolkit rather than as a puzzle to force open: a
plain PE, an SSE2 comparison pipeline, an ELF with a bytecode VM, a protected Python zipapp, a
Rust crate with its own VM, and a JAR with a 31 MB native lock. Per target: triage, the mechanism
(measured), the resolution with black-box controls wherever possible, and the friction the
toolkit hit — fixed **in that round**, not deferred. Summary and links to the full reports:
[reports/sequencia-nivel-1-a-6.5.md](reports/sequencia-nivel-1-a-6.5.md).

## 10. Conventions

- **Existing directories are not moved.** `ghidra/`, `x64dbg/`, `rea-main/` stay at the root —
  moving a working installation is risk without gain. New tools go to `tools/<name>/`. The reason
  and the optional migration path are in [docs/01-arquitetura.md](docs/01-arquitetura.md).
- **Scripts:** `kebab-case.ps1` / `.sh` / `.mjs`, dry-run by default, and never assume
  administrative privilege silently.
- **Docs:** numbered, in pt-BR, with copy-pasteable commands and a verification step.
- **Code language:** identifiers and comments in English; documentation in pt-BR.
- **Outputs:** every analysis artifact goes to `work/<target>/` (Git-ignored); consolidated
  human-readable reports go to `reports/`.

## 11. License and attribution

This repository's own code (scripts, docs, configs) is **MIT** — see [LICENSE](LICENSE),
© UnboxRE contributors.

Third-party tools keep their own licenses and are **not redistributed** here; they are installed
locally by the bootstrap. All credit belongs to their authors — author, license and upstream of
**every** referenced project are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). UnboxRE is
independent and is **not affiliated with or endorsed by** any of them.

> If you package UnboxRE, publish only what is yours (MIT). Redistributing a third-party tool
> means complying with its license — the compatibility matrix is in
> [docs/03-licencas.md](docs/03-licencas.md).

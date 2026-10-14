# Verification report — clean-machine bootstrap + CI guards (2026-10-13)

**Machine:** Windows 11 (build 26200), Git Bash, Windows PowerShell 5.1, Node 24.18
**Scope:** close the gap that made the central promise of the project unproven —
*an agent clones the repo on a clean machine and operates on its own* — and add the
automated guards the definition-of-done asks for.

Everything below was **run on this machine**; the commands and expected output are
included so an independent auditor can reproduce each claim. Where something could
not be exercised, it is listed under "§ 5 Not proven".

---

## 1. What was broken (and is now fixed)

| # | Problem found by inspection | Fix | File(s) |
|---|---|---|---|
| A | **Nothing fetched the four core third-party tools.** `health-check` only reported the dirs missing and told a human to fix it by hand. A clean clone could not work. | `scripts/fetch-tools.ps1` (+ `.sh`) downloads Ghidra, x64dbg, REA and the MCP plugin from their real upstreams, verifies checksums, and installs. `config/tools.json` is the single source of truth. | `scripts/fetch-tools.ps1`, `scripts/fetch-tools.sh`, `config/tools.json` |
| B | Bootstrap `-Profile` names did **not** match the docs (`formats`/`network`/`full`/`wsl` were called differently in code). `-DryRun` was documented but absent. | Profiles accept both the code names and the documented aliases; `-DryRun` added; `fetch` profile added and folded into `core`. | `scripts/bootstrap-windows.ps1` |
| C | `health-check` asked the human to "create a directory" for tools that must be *downloaded*; it also required a `x64dbg-mcp-server-main/` source dir that the release path never creates. | Missing core dirs now point at `fetch-tools.ps1 -Apply`; the MCP check is the installed plugin, not the source dir. | `scripts/health-check.ps1`, `scripts/lib/common.ps1` |
| D | **Five license labels were wrong** (checked against the upstream, see §3). Prior manual audits kept missing these. | Corrected in the matrix and the notices; `scripts/verify-licenses.mjs` now re-checks them from the primary source in CI. | `docs/03-licencas.md`, `THIRD_PARTY_NOTICES.md`, `scripts/verify-licenses.mjs`, `config/licenses.json` |
| E | Docs cited commands/flags/clients/scripts that do not exist (`-Profile dotnet`, `--write`, `--list`, `new-case.mjs`, `pipeline.mjs`, `scan-secrets.mjs`, `--client claude`). | Docs corrected **and** an offline checker now fails CI on any new drift. | `scripts/check-consistency.mjs` + docs |
| F | The project's own intake template carried "finalidade lícita / legítima" wording the doctrine bans. | Rewritten as a technical provenance record. | `scripts/new-case.ps1` |
| G | CI validated structure only — no licence accuracy, no doc/code consistency, no script-syntax gate. | Three jobs extended/added (see §4). | `.github/workflows/ci.yml` |

## 2. The clean-machine path, proven

`fetch-tools.ps1` was run for the one component that was genuinely missing (the MCP
plugin) and installed it from the upstream release into both architectures:

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/fetch-tools.ps1 -Tool x64dbg-mcp -Apply
# [OK] baixado e verificado: x64dbg-MCP-Server-v1.6.zip
# [OK] instalado: release/x64/plugins/x64dbg-MCP-Server.dp64
# [OK] instalado: release/x32/plugins/x64dbg-MCP-Server.dp32
ls x64dbg/release/x64/plugins/   # x64dbg-MCP-Server.dp64
```

Dry-run resolution for all four (proves the upstream URLs are real, without the
570 MB Ghidra download):

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/fetch-tools.ps1
# Ghidra j\u00e1 instalado · x64dbg j\u00e1 instalado · REA j\u00e1 instalado
# x64dbg-MCP: release v1.6 -> x64dbg-MCP-Server-v1.6.zip (1.4 MB) [DRY-RUN]
```

**Key design decision:** the MCP plugin is installed from the **prebuilt upstream
release**, so **Zig is no longer required** to get an MCP bridge working on a clean
machine. Zig is only needed if you choose to build from source (`re-build.ps1`).

`health-check.ps1 -Json`: `{"ok":36,"warn":4,"fail":0}` on this machine after the
install.

## 2b. The REA MCP bridge starts and answers a real call

The REA bridge is stdio, so it can be proven in a headless session (and in CI).
`scripts/smoke-mcp.mjs` speaks the MCP protocol to `rea-main/scripts/rea.mjs mcp`:

```bash
node scripts/smoke-mcp.mjs
# initialize -> serverInfo: {"name":"rea","version":"6.4.0"}
# tools/list -> 172 ferramentas (ex.: annotate_native_function, inspect_native_load_image, ...)
# [OK] a ponte MCP sobe e responde a uma chamada real.  (exit 0)
```

Negative control: a missing entrypoint exits 2 with a clear message. The same
handshake passes against a fresh `npm install rea-agents` (170 tools), which is what
the `mcp-smoke` CI job runs.

## 3. License accuracy — five real errors, corrected from the primary source

`scripts/verify-licenses.mjs` opens the upstream `LICENSE` (raw URL) and cross-checks
GitHub's own detection. On first run it contradicted the documentation on five rows:

| Tool | Was documented | Primary source says | Evidence |
|---|---|---|---|
| ghidriff | Apache-2.0 | **GPL-3.0** | `raw.githubusercontent.com/clearbluejar/ghidriff/main/LICENSE` (GNU GPLv3) |
| YARA-X | Apache-2.0 | **BSD-3-Clause** | `.../VirusTotal/yara-x/main/LICENSE` (BSD text) |
| msynth | BSD-3 | **GPL-2.0** | `.../mrphrazer/msynth/main/LICENSE` (GNU GPLv2) |
| Diaphora | GPL-3.0 | **AGPL-3.0** | `.../joxeankoret/diaphora/master/LICENSE` (GNU AGPLv3) |
| AFL++ | Apache-2.0 | **AGPL-3.0** | `.../AFLplusplus/AFLplusplus/stable/LICENSE` (GNU AGPLv3) |

Also corrected a classification error: **DynamoRIO** was filed under *copyleft* but
its `License.txt` says "Primary DynamoRIO License: BSD" — it moved to the permissive
section.

```bash
node scripts/verify-licenses.mjs
# [OK] 29 licenças declaradas batem com a fonte primária.  (exit 0)
```

Registry: `config/licenses.json` (24 tools) + `config/tools.json` (4 core).
`scripts/check-consistency.mjs` proves **completeness** — every tool the bootstrap
installs has a credit line in `THIRD_PARTY_NOTICES.md`.

## 4. CI — new guards

`.github/workflows/ci.yml` (validated as YAML; jobs `validate`, `licenses`, `secrets`):

- **validate**: mandatory files · `.gitignore` does not swallow docs · MCP JSON valid ·
  shellcheck · `health-check.sh --json` stays pure JSON · **`node --check` every `.mjs`**
  · **`bash -n` every `.sh`** · **PowerShell parser over every `.ps1`** ·
  **`gen-mcp-config.mjs --list --json` emits parseable JSON** · **`check-consistency.mjs`**.
- **licenses** (new job, networked): `verify-licenses.mjs --strict`, using
  `secrets.GITHUB_TOKEN` to lift the API rate limit.
- **mcp-smoke** (new job): installs `rea-agents` from npm and runs
  `smoke-mcp.mjs` — a real MCP `initialize` + `tools/list` handshake against the
  REA bridge.
- **secrets**: unchanged (no third-party binary tracked, no sensitive file tracked).

All of the new steps were run locally with the same commands; every `.ps1` parses
under Windows PowerShell 5.1 and every script exits 0.

**CI result.** On the first push the `validate` job **failed** — and that failure was
the guard working: the link check flagged `docs/05-mcp.md` and
`docs/02-catalogo-ferramentas.md` for linking into `rea-main/` and
`x64dbg-mcp-server-main/`. Those are the fetched third-party trees, gitignored and
absent from a clean checkout **by design**, so the links are not broken — they only
resolve after `fetch-tools`. It passed locally because `rea-main/` existed here: a
perfect illustration of the local/CI gap the job exists to close. The checker was
fixed to ask git which targets it ignores (commit `2f7cb6e`), with a negative
control proving a link to a tracked-but-missing file still fails.

After that fix: **CI run [38467610746](https://github.com/yorickAUTOPECAS/UnboxRE/actions/runs/38467610746)
= success**, all four jobs green (`validate`, `licenses`, `mcp-smoke`, `secrets`).

## 5. Not proven (explicit limitations)

- ~~**x64dbg-MCP live call.** …the live call is a manual step.~~ **Closed the same
  day:** `scripts/start-x64dbg.ps1 -Check` now automates the whole path — it launches
  x64dbg minimised (reusing an already-open instance instead of fighting for the
  port), waits for `:9094`, resolves the token where the plugin actually writes it
  (`x64dbg/release/x64/mcp_config.json`) and runs the real MCP call. Observed:
  `initialize` → *x64dbg-MCP Server 1.6*, `tools/list` → **80 tools**,
  `tools/call GetDebugState` → `isDebugging: false / NO_TARGET`, exit 0. `-Stop`
  ends the instance it launched. What still requires a human: x64dbg is a GUI, so a
  headless CI runner cannot host it — the automation replaces *manual steps*, not the
  GUI itself.
- ~~**VMProtect / Themida positive controls.** Only UPX was sample-tested end to end…~~
  **Closed the same day, in a later round:** official DEMO builds of both protectors
  produced real samples from the same target, and the detector flags all of them —
  two independent VMProtect outputs (one produced headlessly by
  `VMProtect_Con.exe`, so it is reproducible in one line) and one Themida output.
  That round also found and fixed two false positives (`.NET` classified as high
  confidence; high entropy alone reaching the top verdict — 5 of 60 stock Windows
  binaries were mislabeled). See [evidence-packers-vmp-themida.md](evidence-packers-vmp-themida.md).
  Still unproven: the **dynamic** half — those protected artifacts do not load here
  (`0xC000007B`), and the Themida command line (`Themida64.exe /protect x.tmd`)
  hangs without output, so the Themida step needs the GUI.
- **The Linux/WSL half** (ELF, pwndbg, unblob, AFL++) was not exercised: this machine
  has the `wsl` binary but no distro installed.
- **`rea-main` submodule integrations** (binwalk/unblob/jadx-headless MCP) were not
  exercised; the Ghidra provider was (`rea doctor` → `ghidra: healthy`).
- **Full license matrix (~90 rows).** `config/licenses.json` now verifies **69** rows
  against the primary source (was 24), after a second audit round that corrected
  **eight** wrong labels (Keystone, de4dot-cex, Speakeasy, TitanHide, al-khaser,
  PE-bear, D-810, objection). The remaining gap is measured, not hidden:
  `check-consistency.mjs` reports **23/29** of the bootstrap catalog with a verified
  line, and the six left out (Sysinternals Procmon, API Monitor, WSL/Ubuntu, and the
  firmware trio ubireader/sasquatch/firmware-mod-kit) are exactly the ones with no
  readable upstream LICENSE — the registry only holds rows a primary source can
  confirm. See `reports/auditoria-licencas.md` §5.
- ~~**The 570 MB Ghidra / 31 MB x64dbg downloads** were resolved (URLs + asset match)
  but not re-downloaded on this machine…~~ **Closed the same day:** each of the three
  core tools was fetched again from its real upstream, with the existing install moved
  aside first so nothing could be served from what was already there. Evidence (all
  exit 0): REA → `rea-agents@6.4.0` + `npm install` (143 packages) and the MCP bridge
  answering (`smoke-mcp.mjs`: initialize + tools/list 170); x64dbg → snapshot
  `2026-05-27` (30.1 MB) plus the MCP plugin v1.6 into both architectures; Ghidra →
  the cached zip **deleted first** so the 569,649,598-byte `ghidra_12.1.4_PUBLIC_20260921.zip`
  was downloaded again from the network, extracted, and then used for a real headless
  analysis (`analyzeHeadless` → `REPORT: Analysis succeeded`, exit 0). The one part the
  run found broken: `-Tool x64dbg,x64dbg-mcp` under `powershell -File` died with
  "slug desconhecido" (the error message itself crashed on an extra argument), both
  fixed in `fetch-tools.ps1` — the comma form is what `docs/05-mcp.md` documents.

## 6. Reproduce the whole verification

```bash
node scripts/check-consistency.mjs        # offline: docs <-> code <-> licenses, exit 0
node scripts/verify-licenses.mjs          # network: licenses vs primary source, exit 0
node scripts/smoke-mcp.mjs                # REA MCP handshake, exit 0 (needs rea-main)
node scripts/gen-mcp-config.mjs --list --json   # valid JSON, exit 0
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/health-check.ps1 -Json   # fail:0
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/fetch-tools.ps1          # dry-run plan
```

## 7. Round 3 — the 0xC000007B mystery, the unpack pipeline, and a bigger license batch

Full write-ups: [root-cause-0xc000007b.md](root-cause-0xc000007b.md) and
[unpack-iat-upx-case.md](unpack-iat-upx-case.md). Summary of what was measured:

- **The suggested VT-x hypothesis is refuted, with evidence.** This machine is an AMD
  Ryzen 5 5500 with `VirtualizationFirmwareEnabled=True`, SLAT and VM-monitor extensions
  all `True`; `systeminfo` reports every Hyper-V requirement as `Sim`. Independently, the
  failure is a **loader-stage** one: x64dbg maps the image, loads `ntdll`, and the process
  exits with `0xC000007B` **before the entry point** — proven by patching each sample's EP
  to an infinite loop and to `int3` (controls hang/trap; the samples still exit
  `0xC000007B`). A CPU feature cannot cause that.
- **Root cause narrowed and reproduced.** Emptying `SizeOfRawData`/`PointerToRawData` of
  `.rdata` or `.data` on the **working** `clean.exe` reproduces `0xC000007B` exactly;
  emptying `.text`, `fothk`, `.pdata`, `.didat`, `.rsrc` or `.reloc` does not. Both DEMO
  protectors strip exactly those original sections. Independently, clearing the BASERELOC
  directory or the LOADCONFIG directory each produce the same status. Not the cause: imports
  (removing the whole table changes nothing), any data directory, `DllCharacteristics`,
  checksum, path, MOTW, Code Integrity/AppLocker (zero events during the run). The **exact
  ntdll check** is still not identified — that needs loader snaps with Debugging Tools,
  which is not installed; recorded in §7 of the report rather than papered over.
- **New:** `scripts/diagnose-load.mjs` — "protected" and "will it load?" are different
  questions; this answers the second, statically and by running the target. One of its first
  findings was a **false positive** (data directories pointing into an emptied section are
  normal for packers — zeroing them on UPX's own output did not make it load), so that check
  is a `medium` signal, not a verdict.
- **Unpack pipeline proven on a controlled case.** `upx -9 --force` → `upx -d` on a known
  target: 50 DLLs / **315** import thunks restored (the packed stub has 54), a string the
  packer compressed (`fothk`) is back, the restored binary **runs (exit 0)**, and Ghidra
  headless reports `REPORT: Analysis succeeded` while resolving the restored imports. The
  UPX-packed output itself does **not** load on this machine — same error family, reported in
  the case write-up.
- **License registry: 69 → 75 verified rows**, each confirmed against **both** the repo's own
  raw `LICENSE` and GitHub's detection: XED, WinAFL, System Informer, Cutter, pefile, FLOSS.
  Two labels that are easy to get wrong and are now pinned: System Informer is **MIT** (not the
  GPL people assume from its Process Hacker history) and FLOSS is **Apache-2.0**.
  `verify-licenses.mjs` → `[OK] 75`; `check-consistency.mjs` → `[OK] 187 verificações`.
- **Agent onboarding added:** [AGENTS.md](../AGENTS.md) and [CLAUDE.md](../CLAUDE.md) at the
  repo root — the non-negotiables, the repo map, the commands that matter, and the traps this
  project already paid for (so a fresh clone needs no manual explanation).
- **Not done / blocked:** memory dump + IAT repair with Scylla was **not** exercised end to end
  (UPX's canonical path restores the file, so no dump is needed; the GUI step of Scylla is
  manual and was not automated) — see §5 of the case write-up. The dynamic confirmation of the
  VMProtect/Themida samples remains blocked because those images do not load here at all.

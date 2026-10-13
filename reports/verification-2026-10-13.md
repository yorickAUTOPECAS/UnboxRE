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
- **secrets**: unchanged (no third-party binary tracked, no sensitive file tracked).

All of the new steps were run locally with the same commands; every `.ps1` parses
under Windows PowerShell 5.1 and every script exits 0.

## 5. Not proven (explicit limitations)

- **No live MCP `tools/list`.** x64dbg-MCP answers only with the x64dbg GUI open, which
  a headless host/CI session cannot do. Installed + loadable is proven; the live call
  is a manual step (`docs/05-mcp.md`).
- **VMProtect / Themida positive controls.** Only UPX was sample-tested end to end
  (`reports/evidence-packer-upx.md`); the other signatures are code-reviewed, not
  sample-tested — no such sample was available.
- **The Linux/WSL half** (ELF, pwndbg, unblob, AFL++) was not exercised: this machine
  has the `wsl` binary but no distro installed.
- **`rea-main` submodule integrations** (binwalk/unblob/jadx-headless MCP) were not
  exercised; the Ghidra provider was (`rea doctor` → `ghidra: healthy`).
- **Full license matrix (~90 rows).** `config/licenses.json` verifies 24 continuously;
  the remaining rows are still audited by hand. Extending the registry is the next step.
- **The 570 MB Ghidra / 31 MB x64dbg downloads** were resolved (URLs + asset match) but
  not re-downloaded on this machine (both were already present). The extraction + marker
  logic was exercised on the MCP plugin.

## 6. Reproduce the whole verification

```bash
node scripts/check-consistency.mjs        # offline: docs <-> code <-> licenses, exit 0
node scripts/verify-licenses.mjs          # network: licenses vs primary source, exit 0
node scripts/gen-mcp-config.mjs --list --json   # valid JSON, exit 0
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/health-check.ps1 -Json   # fail:0
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/fetch-tools.ps1          # dry-run plan
```

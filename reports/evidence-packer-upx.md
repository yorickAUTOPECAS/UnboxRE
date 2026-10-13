# Evidence — a real workflow executed against a real target

**Date:** 2026-10-13
**Machine:** Windows 11 (build 26200), Git Bash, Windows PowerShell 5.1
**Goal:** satisfy the "at least one documented workflow executed against a real
target, with evidence" acceptance criterion — not described, run.

Two things are proven below, on a real Windows PE (not a fixture):

1. **Static engine works end to end** — Ghidra 12.1.4 `analyzeHeadless` imports
   and fully analyses the target (`REPORT: Analysis succeeded`).
2. **Protection detection works** — `scripts/identify-protections.mjs` reports
   "no known signature" on the clean target and a high-confidence **UPX** hit on a
   UPX-packed control, using only the file itself (no external tool).

Everything is reproducible with the commands shown. The binaries live in
`work/packer-demo/` (gitignored — third-party/target material never enters Git).

---

## 1. Target

`C:\Windows\System32\where.exe`, copied to `work/packer-demo/clean-where.exe`.

```bash
cp /c/Windows/System32/where.exe work/packer-demo/clean-where.exe
sha256sum work/packer-demo/clean-where.exe
# f51fab8041e5023d7290b540a2106f051ef0bd2bc3443c9daf318628b560fa29  clean-where.exe
```

## 2. Static analysis — Ghidra headless

```bash
export JAVA_HOME='C:\Program Files\Java\jdk-21.0.12'
mkdir -p work/packer-demo/ghidra-proj
./ghidra/ghidra_12.1.4_PUBLIC/support/analyzeHeadless.bat \
  "$(cygpath -w "$PWD/work/packer-demo/ghidra-proj")" demo \
  -import "$(cygpath -w "$PWD/work/packer-demo/clean-where.exe")" -deleteProject
```

Observed (excerpt):

```
INFO  Headless startup complete (2814 ms)
INFO  ANALYZING all memory and code: file:///.../clean-where.exe
      Create Function                            0.014 secs
      Decompiler Switch Analysis                 1.650 secs
      Function ID                                0.260 secs
INFO  REPORT: Analysis succeeded for file: file:///.../clean-where.exe
exit 0
```

✅ The static pipeline runs against a real binary with no manual steps. The
`REA` provider finds the same Ghidra install (`node rea-main/scripts/rea.mjs
doctor` reports `ghidra: healthy`).

## 3. Protection triage — clean control

```bash
node scripts/identify-protections.mjs work/packer-demo/clean-where.exe
```

```
  seções: .text .rdata .data .pdata .didat .rsrc .reloc
  [ok] nenhuma assinatura de packer/protetor conhecida.
  Veredito: sem assinatura conhecida
```

JSON verdict: `sem assinatura conhecida`, 0 findings.

## 4. Protection triage — UPX positive control

UPX was fetched from its own upstream release (not vendored) purely to build a
positive control:

```bash
curl -sSL -o .cache/downloads/upx.zip \
  https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-win64.zip
unzip -q .cache/downloads/upx.zip -d .cache/downloads/upx
# note: the Windows system binaries are CFG-enabled, which UPX refuses by
# default; --force disables CFG so the packed control can be produced.
./.cache/downloads/upx/upx-5.2.1-win64/upx.exe --force \
  -o work/packer-demo/packed.exe work/packer-demo/clean-where.exe
# 65536 -> 23040  35.16%  win64/pe  packed.exe

sha256sum work/packer-demo/packed.exe
# feb7b9db8397220d1cd92be12086bf5346efbec3ca0d6b02c0433ebba1ee7f56  packed.exe
node scripts/identify-protections.mjs work/packer-demo/packed.exe
```

```
  seções:
    UPX0       virt=49152    raw=0        entropia=0    WX
    UPX1       virt=20480    raw=19456    entropia=7.82 WX
    .rsrc      virt=4096     raw=2560     entropia=4.18 W-
  [!!] UPX (high) — seções UPX0/UPX1 ou marcador UPX!
  [? ] Entry point fora de .text (medium) — entrypoint cai em "UPX1"
  [? ] Seção de código gravável (medium) — "UPX1" é W+X
  [? ] Alta entropia (low) — seções com entropia >= 7.2: UPX1
  [? ] Seções virtuais sem dados no arquivo (medium) — UPX0
  Veredito: PROVAVELMENTE PROTEGIDO
```

✅ **Detection coverage** for the UPX class (the acceptance criterion names UPX,
VMProtect and Themida). The signature table in `scripts/identify-protections.mjs`
also covers VMProtect (`.vmp0/1/2`, `VMProtect`), Themida/WinLicense
(`.themida/.winlice`, `Themida`), ASPack, PECompact, MPRESS, Petite, Enigma and
the .NET CLR header. This is a first-pass triage signal; dynamic confirmation is
still the ground truth, as `docs/06-workflows.md` describes.

## 5. What this does NOT prove

- No VMProtect/Themida **sample** was available to run a positive control for
  those two — only UPX was confirmed end to end. The signature table for the
  others is code-reviewed, not sample-tested.
- The Linux/WSL half of the toolkit (ELF, pwndbg, unblob) was not exercised —
  this machine has the WSL binary but no distro installed.
- x64dbg-MCP's live `tools/list` was not exercised: it needs the x64dbg GUI open,
  which a headless CI/host session cannot do. The plugin **installs and loads**
  from the upstream release (see `reports/verification-2026-10-13.md`), which is
  the part that could be automated; the live call is a manual step.

## Reproduce in one line

```bash
bash scripts/fetch-tools.ps1 2>/dev/null; node scripts/identify-protections.mjs <seu-alvo.exe>
```

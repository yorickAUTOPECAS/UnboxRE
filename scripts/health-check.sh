#!/usr/bin/env bash
# =============================================================================
# scripts/health-check.sh — diagnóstico do UnboxRE (Git Bash ou WSL/Linux).
#
# Espelho do health-check.ps1 para quando você está no lado POSIX. Somente
# leitura; não instala nem modifica nada. Exit 0 = sem FAIL, 1 = há FAIL.
#
# Uso:
#   bash scripts/health-check.sh
#   bash scripts/health-check.sh --json > reports/health.json
# =============================================================================
set -uo pipefail

JSON=0
[[ "${1:-}" == "--json" ]] && JSON=1

if [[ -t 1 && $JSON -eq 0 ]]; then
  C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_FAIL=$'\033[31m'
  C_INFO=$'\033[36m'; C_RST=$'\033[0m'
else
  C_OK=; C_WARN=; C_FAIL=; C_INFO=; C_RST=
fi

counts=(0 0 0)  # ok warn fail
json_items=()

# Em --json o stdout tem que conter SÓ o objeto JSON (o health-check.ps1 faz o
# mesmo, acumulando os resultados), então os printers ficam mudos nesse modo; as
# contagens e os itens continuam sendo acumulados normalmente.
say() { [[ $JSON -eq 1 ]] && return 0; printf '  [%-4s] %s\n' "$1" "$2"; }
ok()   { counts[0]=$((counts[0]+1)); say "OK"   "${C_OK}$1${C_RST}";     json_items+=("{\"level\":\"OK\",\"message\":\"${1//\"/\\\"}\"}"); }
warn() { counts[1]=$((counts[1]+1)); say "WARN" "${C_WARN}$1${C_RST}";   json_items+=("{\"level\":\"WARN\",\"message\":\"${1//\"/\\\"}\"}"); }
fail() { counts[2]=$((counts[2]+1)); say "FAIL" "${C_FAIL}$1${C_RST}";   json_items+=("{\"level\":\"FAIL\",\"message\":\"${1//\"/\\\"}\"}"); }
info() { say "INFO" "${C_INFO}$1${C_RST}"; }
section() { [[ $JSON -eq 1 ]] && return 0; printf '\n%s\n' "${C_INFO}── $1 ${C_RST}"; }

have() { command -v "$1" >/dev/null 2>&1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ $JSON -eq 0 ]]; then
  line=$(printf '─%.0s' {1..68})
  printf '\n%s\n  UnboxRE — health check (POSIX)\n  raiz: %s\n%s\n' "$C_INFO$line$C_RST" "$REPO_ROOT" "$C_INFO$line$C_RST"
fi

# ─── 1. Layout ───────────────────────────────────────────────────────────────
section "1. Layout"
for d in docs scripts config tools work reports; do
  if [[ -e "$REPO_ROOT/$d" ]]; then ok "layout:$d presente"
  else warn "layout:$d ausente (crie com o bootstrap ou manualmente)"; fi
done
for d in ghidra x64dbg rea-main x64dbg-mcp-server-main; do
  if [[ -e "$REPO_ROOT/$d" ]]; then ok "núcleo:$d presente"
  else warn "núcleo:$d ausente"; fi
done

# ─── 2. Toolchain ────────────────────────────────────────────────────────────
section "2. Toolchain"
for t in node npm git python3 gdb objdump strings file; do
  if have "$t"; then ok "$t: $(command -v "$t")"
  else warn "$t ausente"; fi
done
if have java || [[ -n "${JAVA_HOME:-}" ]]; then ok "java/JAVA_HOME presentes"
else warn "sem JDK — Ghidra/REA precisam de um"; fi
for t in zig cmake ninja cargo; do
  if have "$t"; then ok "$t presente"; else warn "$t ausente (necessário p/ builds)"; fi
done

# ─── 3. Núcleo ───────────────────────────────────────────────────────────────
section "3. Núcleo"
ghidra_dir="$(find "$REPO_ROOT/ghidra" -maxdepth 1 -type d -name 'ghidra_*_PUBLIC' 2>/dev/null | head -1)"
if [[ -n "$ghidra_dir" ]]; then
  ok "ghidra: $(basename "$ghidra_dir")"
  [[ -x "$ghidra_dir/support/analyzeHeadless" ]] && ok "ghidra headless presente" || warn "analyzeHeadless ausente"
else
  fail "ghidra/ghidra_*_PUBLIC não encontrado"
fi
if [[ -e "$REPO_ROOT/x64dbg/release/x64/x64dbg.exe" || -e "$REPO_ROOT/x64dbg/release/x64/x64dbg" ]]; then
  ok "x64dbg presente"
else
  warn "x64dbg não encontrado (é Windows-only; normal no lado POSIX)"
fi
[[ -f "$REPO_ROOT/rea-main/scripts/rea.mjs" ]] && ok "rea.mjs presente" || fail "rea-main/scripts/rea.mjs ausente"
[[ -d "$REPO_ROOT/rea-main/node_modules" ]] && ok "rea: node_modules" || warn "rea não construído (rode re-build.ps1)"
if find "$REPO_ROOT/x64dbg-mcp-server-main" -maxdepth 3 \( -iname '*.dp64' -o -iname '*.dp32' \) 2>/dev/null | grep -q .; then
  ok "x64dbg-MCP compilado"
else
  warn "x64dbg-MCP não compilado (rode re-build.ps1)"
fi

# ─── 4. Catálogo ─────────────────────────────────────────────────────────────
section "4. Ferramentas do catálogo"
present=0; total=0
for t in r2 rizin upx yara capa frida jadx apktool binwalk unblob wasm2wat mitmdump tshark de4dot qiling; do
  total=$((total+1))
  if have "$t"; then present=$((present+1)); ok "catalog:$t"; else info "catalog:$t não instalada"; fi
done
info "catalog: $present/$total no PATH"

# ─── 5. Ambiente ─────────────────────────────────────────────────────────────
section "5. Ambiente"
for v in UNBOXRE_WORKSPACE UNBOXRE_WORK GHIDRA_INSTALL_DIR JAVA_HOME; do
  if [[ -n "${!v:-}" ]]; then ok "env:$v definida"; else info "env:$v não definida"; fi
done
if [[ -f "$REPO_ROOT/config/env/unboxre.env" ]]; then ok "config/env/unboxre.env presente"
elif [[ -f "$REPO_ROOT/config/env/unboxre.env.example" ]]; then warn "unboxre.env ausente (copie o .example)"
else fail "unboxre.env.example ausente"; fi

# ─── Resumo ──────────────────────────────────────────────────────────────────
if [[ $JSON -eq 1 ]]; then
  printf '{"root":"%s","summary":{"ok":%d,"warn":%d,"fail":%d},"items":[%s]}\n' \
    "$REPO_ROOT" "${counts[0]}" "${counts[1]}" "${counts[2]}" "$(IFS=,; echo "${json_items[*]}")"
else
  # A cor do bloco de resumo segue a pior severidade encontrada.
  col=$C_OK; [[ ${counts[1]} -gt 0 ]] && col=$C_WARN; [[ ${counts[2]} -gt 0 ]] && col=$C_FAIL
  printf '\n%s%s%s\n' "$col" "$(printf '─%.0s' {1..68})" "$C_RST"
  printf '  OK: %s%d%s   WARN: %s%d%s   FAIL: %s%d%s\n' \
    "$C_OK" "${counts[0]}" "$C_RST" "$C_WARN" "${counts[1]}" "$C_RST" "$C_FAIL" "${counts[2]}" "$C_RST"
  printf '\n'
fi

[[ ${counts[2]} -gt 0 ]] && exit 1 || exit 0

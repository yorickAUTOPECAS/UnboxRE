#!/usr/bin/env bash
# =============================================================================
#  scripts/fetch-tools.sh — clean-machine fetch of the CORE tools, from bash.
#
#  Windows (Git Bash / MSYS): delegates to fetch-tools.ps1 so there is exactly
#  ONE install implementation. bash on Windows is a convenience shell, not a
#  second source of truth.
#
#  Linux / WSL: x64dbg is Windows-only, so only ghidra and rea apply here; the
#  script fetches those two and reports the others as not-applicable. The
#  manifest config/tools.json is still the source of truth (parsed with node).
#
#  Usage:
#    bash scripts/fetch-tools.sh                 # dry-run plan
#    bash scripts/fetch-tools.sh --apply         # install
#    bash scripts/fetch-tools.sh --tool rea --apply
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
MANIFEST="$ROOT/config/tools.json"

APPLY=0
TOOLS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply|-a) APPLY=1; shift ;;
    --force|-f) FORCE=1; shift ;;
    --tool|-t) TOOLS+=("$2"); shift 2 ;;
    --all) shift ;;
    -h|--help)
      sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "argumento desconhecido: $1" >&2; exit 2 ;;
  esac
done

# ── Windows: hand off to the PowerShell implementation ───────────────────────
if command -v powershell.exe >/dev/null 2>&1; then
  args=()
  [[ $APPLY -eq 1 ]] && args+=("-Apply")
  [[ "${FORCE:-0}" -eq 1 ]] && args+=("-Force")
  if [[ ${#TOOLS[@]} -gt 0 ]]; then args+=("-Tool" "${TOOLS[@]}"); fi
  exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$HERE/fetch-tools.ps1" "${args[@]}"
fi

# ── Linux / WSL ──────────────────────────────────────────────────────────────
command -v node >/dev/null 2>&1 || { echo "node é necessário para ler o manifest" >&2; exit 2; }
[[ -f "$MANIFEST" ]] || { echo "manifest ausente: $MANIFEST" >&2; exit 2; }

field() { node -e "const t=require('$MANIFEST').tools['$1'];console.log($2)" ; }

have() { [[ -z "$1" ]] && return 1; return 0; }
in_selection() {
  [[ ${#TOOLS[@]} -eq 0 ]] && return 0
  for t in "${TOOLS[@]}"; do [[ "$t" == "$1" || "$t" == "all" ]] && return 0; done
  return 1
}

mkdir -p "$ROOT/.cache/downloads"

install_github_zip() {
  local slug="$1" dest="$2" marker="$3" repo pattern
  repo="$(field "$slug" "t.repo")"
  pattern="$(field "$slug" "t.assetPattern")"
  echo "── $slug"
  if [[ -e "$ROOT"/$marker && "${FORCE:-0}" -ne 1 ]]; then echo "   [OK] já instalado"; return 0; fi
  local url name
  url="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" \
    | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);const re=new RegExp(process.argv[1]);const a=j.assets.find(x=>re.test(x.name));if(a)console.log(a.browser_download_url)})" "$pattern")"
  if [[ -z "$url" ]]; then echo "   [FAIL] asset não encontrado (/$(printf %s "$pattern")/)"; return 1; fi
  name="$(basename "${url%%\?*}")"
  echo "   baixaria: $url"
  if [[ $APPLY -eq 1 ]]; then
    curl -fL --retry 3 -o "$ROOT/.cache/downloads/$name" "$url"
    mkdir -p "$ROOT/$dest"
    unzip -o -q "$ROOT/.cache/downloads/$name" -d "$ROOT/$dest"
    echo "   [OK] extraído em $dest"
  fi
}

install_npm() {
  local slug="$1" dest="$2" pkg registry tarball
  pkg="$(field "$slug" "t.package")"
  registry="$(field "$slug" "t.registry")"
  echo "── $pkg (npm)"
  if [[ -e "$ROOT/$dest/scripts/rea.mjs" && "${FORCE:-0}" -ne 1 ]]; then echo "   [OK] já instalado"; return 0; fi
  tarball="$(curl -fsSL "$registry/$pkg" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);console.log(j.versions[j['dist-tags'].latest].dist.tarball)})")"
  echo "   baixaria: $tarball"
  if [[ $APPLY -eq 1 ]]; then
    curl -fL --retry 3 -o "$ROOT/.cache/downloads/$pkg.tgz" "$tarball"
    mkdir -p "$ROOT/$dest"
    tar -xzf "$ROOT/.cache/downloads/$pkg.tgz" -C "$ROOT/$dest" --strip-components=1
    ( cd "$ROOT/$dest" && npm install --omit=dev --ignore-scripts --no-audit --no-fund )
    echo "   [OK] instalado em $dest"
  fi
}

echo "UnboxRE — fetch de ferramentas (Linux/Windows-GitBash)"
echo "  modo: $([[ $APPLY -eq 1 ]] && echo APLICANDO || echo dry-run)"

rc=0
if in_selection ghidra; then
  install_github_zip ghidra ghidra 'ghidra/*/support/analyzeHeadless.bat' || rc=1
fi
if in_selection rea; then
  install_npm rea rea-main || rc=1
fi
for slug in x64dbg x64dbg-mcp; do
  if in_selection "$slug"; then
    echo "── $slug: não se aplica a Linux (x64dbg é Windows-only)"
  fi
done

[[ $APPLY -eq 0 ]] && echo "  DRY-RUN. Rode com --apply para instalar."
exit $rc

#!/usr/bin/env bash
# =============================================================================
# scripts/bootstrap-wsl.sh — provisiona o lado Linux (WSL/Ubuntu) do UnboxRE.
#
# Por que existe: metade do catálogo (iwndbg/gef, angr, Qiling, pwntools, unblob,
# pwndbg, tshark headless) é mais confiável em Linux, e o Ghidra headless/REA
# rodam melhor quando há um ambiente POSIX real. Este script instala o que o
# host Windows não instala direito.
#
# Uso (de dentro do WSL):
#   bash scripts/bootstrap-wsl.sh                 # dry-run (mostra o plano)
#   bash scripts/bootstrap-wsl.sh --apply         # instala de fato (pede confirmação)
#   bash scripts/bootstrap-wsl.sh --apply --yes   # instala sem pedir confirmação
#   bash scripts/bootstrap-wsl.sh --apply --profile static
#
# Perfis: core | static | dynamic | mobile | firmware | net | all
#
# Idempotente: cada passo checa "já instalado?" antes de agir. Rodar duas vezes
# não quebra nada.
#
# Executado de dentro do WSL, o caminho do repositório Windows aparece em
# /mnt/c/... — o script resolve a raiz a partir da própria localização.
# =============================================================================
set -uo pipefail

APPLY=0
PROFILE="core"
ASSUME_YES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply|-a)   APPLY=1; shift ;;
    --yes|-y)     ASSUME_YES=1; shift ;;
    --profile|-p) PROFILE="${2:-core}"; shift 2 ;;
    --help|-h)
      # Imprime o cabeçalho inteiro (só as linhas de comentário do topo), sem
      # depender de quantas linhas ele ocupa hoje.
      awk 'NR > 1 && /^#/ { print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "argumento desconhecido: $1" >&2; exit 2 ;;
  esac
done

# ─── Cores e helpers ─────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_FAIL=$'\033[31m'
  C_INFO=$'\033[36m'; C_DIM=$'\033[90m'; C_RST=$'\033[0m'
else
  C_OK=; C_WARN=; C_FAIL=; C_INFO=; C_DIM=; C_RST=
fi

COUNT_OK=0; COUNT_WARN=0; COUNT_FAIL=0

say()  { printf '  [%-4s] %s\n' "$1" "$2"; }
ok()   { say "OK"   "${C_OK}$1${C_RST}"; COUNT_OK=$((COUNT_OK+1)); }
warn() { say "WARN" "${C_WARN}$1${C_RST}"; COUNT_WARN=$((COUNT_WARN+1)); }
fail() { say "FAIL" "${C_FAIL}$1${C_RST}"; COUNT_FAIL=$((COUNT_FAIL+1)); }
info() { say "INFO" "${C_INFO}$1${C_RST}"; }
dim()  { printf '  %s%s%s\n' "$C_DIM" "$1" "$C_RST"; }

section() { printf '\n── %s \n' "$1"; }

banner() {
  local line
  line=$(printf '─%.0s' {1..68})
  printf '\n%s\n  %s\n  %s\n%s\n' "$C_INFO$line$C_RST" "$1" "$2" "$C_INFO$line$C_RST"
}

have() { command -v "$1" >/dev/null 2>&1; }

# ─── Localização do repositório ──────────────────────────────────────────────
# scripts/ está na raiz do toolkit; o script pode ser chamado de qualquer cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOGDIR="$REPO_ROOT/work/_bootstrap-logs"
mkdir -p "$LOGDIR" 2>/dev/null || true
LOG="$LOGDIR/wsl-$(date +%Y%m%d-%H%M%S).log"

# ─── Requisito: estar no Linux ───────────────────────────────────────────────
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERRO: rode este script DENTRO do WSL (Ubuntu), não no Git Bash do Windows." >&2
  echo "  PS> wsl -d Ubuntu -- bash -lc 'cd $(wslpath -u \"$REPO_ROOT\") && bash scripts/bootstrap-wsl.sh --apply'" >&2
  exit 2
fi

if [[ $EUID -eq 0 ]]; then
  SUDO=""
else
  if have sudo; then SUDO="sudo"; else
    fail "sem sudo e sem ser root — não é possível instalar pacotes"
    exit 2
  fi
fi

SUDO_KEEPALIVE_PID=""
cleanup() { [[ -n "$SUDO_KEEPALIVE_PID" ]] && kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true; }
trap cleanup EXIT

# ─── apt helpers ─────────────────────────────────────────────────────────────
APT_UPDATED=0
apt_update() {
  [[ $APT_UPDATED -eq 1 ]] && return 0
  if [[ $APPLY -eq 1 ]]; then
    info "apt-get update"
    $SUDO apt-get update -qq >>"$LOG" 2>&1 || { fail "apt-get update falhou (veja $LOG)"; return 1; }
  else
    dim "DRY-RUN: $SUDO apt-get update"
  fi
  APT_UPDATED=1
}

apt_install() {
  local pkg="$1" why="$2"
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    ok "apt:$pkg — já instalado ($why)"
    return 0
  fi
  if [[ $APPLY -eq 1 ]]; then
    apt_update || return 1
    info "apt-get install $pkg — $why"
    if $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" >>"$LOG" 2>&1; then
      ok "apt:$pkg instalado"
    else
      fail "apt:$pkg falhou (veja $LOG)"
      return 1
    fi
  else
    info "apt-get install $pkg — $why"
  fi
}

pip_user_install() {
  local pkg="$1" probe="$2" why="$3"
  if have "$probe"; then
    ok "pip:$pkg — já presente ($probe)"
    return 0
  fi
  if [[ $APPLY -eq 1 ]]; then
    info "pip install --user $pkg — $why"
    if python3 -m pip install --user --upgrade "$pkg" >>"$LOG" 2>&1; then
      ok "pip:$pkg instalado"
    else
      warn "pip:$pkg falhou (veja $LOG)"
    fi
  else
    info "pip install --user $pkg — $why"
  fi
}

# ─── Início ──────────────────────────────────────────────────────────────────
banner "UnboxRE — bootstrap WSL (Ubuntu)" "perfil: $PROFILE   raiz: $REPO_ROOT"

if [[ $APPLY -eq 0 ]]; then
  printf '  modo: %sDRY-RUN%s — rode com --apply para instalar\n' "$C_WARN" "$C_RST"
else
  printf '  modo: %sAPPLY%s — instalando; log em %s\n' "$C_OK" "$C_RST" "$LOG"
fi

# Instalar pacotes altera o sistema do WSL, então confirmamos antes — exceto com
# --yes ou quando não há terminal (CI, pipes, `wsl -- bash -c`), para não travar.
if [[ $APPLY -eq 1 && $ASSUME_YES -eq 0 && -t 0 ]]; then
  printf '  Isto vai instalar pacotes no WSL (sudo). Continuar? [s/N] '
  read -r resposta
  case "$resposta" in
    s|S|y|Y|sim|Sim|SIM) ;;
    *) printf '  abortado; nada foi alterado.\n'; exit 0 ;;
  esac
fi

# ─── 0. Base ─────────────────────────────────────────────────────────────────
section "0. Base do sistema"
apt_install build-essential "compilador C/C++ para builds nativos"
apt_install git           "checkout de repositórios e submódulos"
apt_install curl          "download de ferramentas e instaladores"
apt_install ca-certificates "cadeia de certificados (downloads HTTPS)"
apt_install unzip         "extração de releases .zip"
apt_install python3       "base para as ferramentas Python do catálogo"
apt_install python3-pip   "instalação de pacotes Python"
apt_install python3-venv  "ambientes isolados por alvo"

# ─── 1. core ─────────────────────────────────────────────────────────────────
if [[ "$PROFILE" == "core" || "$PROFILE" == "all" ]]; then
  section "1. Core — toolchain Linux"
  apt_install gdb           "debugger base para pwndbg/gef"
  apt_install xxd           "hexdump para inspeção rápida (vim-common)"
  apt_install file          "identificação de tipo de arquivo"
  apt_install binutils      "objdump, readelf, strings, nm"
  apt_install patchelf      "relink de ELF e ajuste de RPATH/interp"
  apt_install nasm          "montador para patches e shells de teste"
fi

# ─── 2. static ───────────────────────────────────────────────────────────────
if [[ "$PROFILE" == "static" || "$PROFILE" == "all" ]]; then
  section "2. Estática — desmontagem/diff Linux"
  apt_install radare2       "CLI/scriptável e radiff2 para diff de ELF"
  apt_install rizin         "fork do radare2 (quando no repositório)"
  apt_install yara          "assinaturas no lado Linux"
  # radare2 no Ubuntu costuma estar em versão antiga; alternativa via pip do rabin2
  pip_user_install "lief" "lief" "parsing e reescrita de PE/ELF/Mach-O"
  pip_user_install "capstone" "cstool" "desmontador multi-arquitetura via Python"
fi

# ─── 3. dynamic ──────────────────────────────────────────────────────────────
if [[ "$PROFILE" == "dynamic" || "$PROFILE" == "all" ]]; then
  section "3. Dinâmica — debug/emulação Linux"
  # pwndbg e gef: instalar em um venv dedicado evita poluir o Python do sistema
  PWNDBG_DIR="$HOME/.local/share/pwndbg"
  GEF_DIR="$HOME/.local/share/gef"
  if [[ -f "$HOME/.gdbinit" ]] && grep -qE 'pwndbg|gef' "$HOME/.gdbinit" 2>/dev/null; then
    ok "gdbinit — pwndbg/gef já referenciados"
  else
    if [[ $APPLY -eq 1 ]]; then
      if [[ ! -d "$PWNDBG_DIR" ]]; then
        git clone --depth 1 https://github.com/pwndbg/pwndbg "$PWNDBG_DIR" >>"$LOG" 2>&1 || true
      fi
      if [[ -x "$PWNDBG_DIR/setup.sh" ]]; then
        (cd "$PWNDBG_DIR" && ./setup.sh >>"$LOG" 2>&1) && ok "pwndbg configurado" || warn "pwndbg: setup falhou (veja $LOG)"
      fi
    else
      info "git clone pwndbg → $PWNDBG_DIR + setup.sh"
    fi
  fi
  # gef: alternativa leve ao pwndbg. Clonamos em GEF_DIR sem mexer no ~/.gdbinit
  # (o pwndbg já registrou o hook dele), então o gef fica disponível sob demanda:
  #   gdb -q -ex "source $GEF_DIR/gef.py" ./alvo
  if [[ -f "$GEF_DIR/gef.py" ]]; then
    ok "gef presente em $GEF_DIR — ative com: gdb -q -ex \"source $GEF_DIR/gef.py\" ./alvo"
  elif [[ $APPLY -eq 1 ]]; then
    if git clone --depth 1 https://github.com/hugsy/gef "$GEF_DIR" >>"$LOG" 2>&1; then
      ok "gef instalado em $GEF_DIR"
    else
      warn "gef: clone falhou (veja $LOG)"
    fi
  else
    info "git clone gef → $GEF_DIR (uso sob demanda, sem conflitar com o pwndbg)"
  fi
  pip_user_install "pwntools" "pwn" "exploit dev e scripts de análise"
  pip_user_install "frida-tools" "frida" "instrumentação DBI no Linux"
  pip_user_install "angr" "angr" "execução simbólica (CFG + constraint solving)"
  pip_user_install "qiling" "qiling" "emulação de sistema (rootfs Linux/Windows)"
  pip_user_install "unicorn" "unicorn" "engine de emulação CPU (base do Qiling)"
  pip_user_install "keystone-engine" "kstool" "montador (patches em memória)"
  pip_user_install "ropgadget" "ROPgadget" "busca de gadgets para ROP"
fi

# ─── 4. mobile ───────────────────────────────────────────────────────────────
if [[ "$PROFILE" == "mobile" || "$PROFILE" == "all" ]]; then
  section "4. Mobile — Android"
  apt_install default-jdk   "runtime para apktool/jadx"
  apt_install apktool       "APK → smali + recursos"
  apt_install android-sdk-build-tools "aapt, d8 e afins (quando disponível)"
  pip_user_install "frida-tools" "frida" "hook em apps Android"
fi

# ─── 5. firmware ─────────────────────────────────────────────────────────────
if [[ "$PROFILE" == "firmware" || "$PROFILE" == "all" ]]; then
  section "5. Firmware / IoT"
  apt_install binwalk       "recon e extração de firmware (recursivo)"
  apt_install squashfs-tools "montar/extrair SquashFS (comum em roteadores)"
  apt_install cpio          "extrair initramfs"
  apt_install mtd-utils     "ferramentas de memória flash NAND/NOR"
  apt_install device-tree-compiler "DTB → DTS (análise de embedded)"
  pip_user_install "unblob" "unblob" "extração insdustrial de firmware (mais robusto que binwalk)"
  pip_user_install "jefferson" "jefferson" "extração de JFFS2"
fi

# ─── 6. net ──────────────────────────────────────────────────────────────────
if [[ "$PROFILE" == "net" || "$PROFILE" == "all" ]]; then
  section "6. Rede e protocolos"
  apt_install tshark        "captura/dissecação headless"
  apt_install tcpdump       "captura crua"
  apt_install socat         "relay de sockets para MITM"
  apt_install ncat          "netcat — probes de protocolo"
  pip_user_install "mitmproxy" "mitmdump" "interceptação HTTP(S) para reverter protocolos"
  pip_user_install "scapy" "scapy" "forjar/injetar pacotes"
fi

# ─── Verificação rápida ──────────────────────────────────────────────────────
section "Verificação rápida"
for t in gdb python3 pip3 r2 objdump strings tshark; do
  if have "$t"; then ok "$t presente"; else warn "$t ausente (depende do perfil)"; fi
done

# ─── Resumo ──────────────────────────────────────────────────────────────────
printf '\n%s\n' "$(printf '─%.0s' {1..68})"
printf '  OK: %s%d%s   WARN: %s%d%s   FAIL: %s%d%s\n' \
  "$C_OK" "$COUNT_OK" "$C_RST" "$C_WARN" "$COUNT_WARN" "$C_RST" "$C_FAIL" "$COUNT_FAIL" "$C_RST"

if [[ $APPLY -eq 0 ]]; then
  printf '\n  Isto foi um DRY-RUN. Rode de novo com --apply para instalar.\n'
else
  printf '\n  Log completo: %s\n' "$LOG"
  printf '  Valide do lado Windows:  PS> .\\scripts\\health-check.ps1\n'
fi
printf '\n'

exit $(( COUNT_FAIL > 0 ? 1 : 0 ))

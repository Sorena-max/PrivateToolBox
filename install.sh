#!/usr/bin/env bash
# PrivateToolBox installer / updater / uninstaller.
#
#   curl -fsSL https://raw.githubusercontent.com/Sorena-max/PrivateToolBox/main/install.sh | sudo bash
#
# GitHub: Sorena-max. Free software (MIT); selling it or charging for it is prohibited.
# This script only copies files into /opt/privatetoolbox and adds a command.
# It does not change your server settings; that happens when you run privatetoolbox.

set -Eeuo pipefail

PT_VERSION="0.1.1"
REPO_SLUG="Sorena-max/PrivateToolBox"
APP_DIR="/opt/privatetoolbox"
STATE_DIR="/var/lib/privatetoolbox"
BIN_FILE="/usr/local/bin/privatetoolbox"
MIN_PY="3.8"

COMMAND="install"
REF="${PT_REF:-main}"
LOCAL_SOURCE=""
NON_INTERACTIVE=0
PURGE=0
NO_CLEAR=0
FAST=0
SLOW=0
PM=""
TMP_DIR=""
SRC=""

UI_COLOR=0
UI_UTF8=0
UI_256=0
COLS=64
C_RED=""; C_GRN=""; C_YLW=""; C_CYN=""; C_DIM=""; C_BLD=""; C_OFF=""
SYM_OK="[OK]"; SYM_BAD="[X]"; SYM_WARN="[!]"; SYM_DOT="-"; RULE_CH="-"

setup_ui() {
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
    UI_COLOR=1
    C_RED=$'\033[1;31m'; C_GRN=$'\033[1;32m'; C_YLW=$'\033[1;33m'
    C_CYN=$'\033[1;36m'; C_DIM=$'\033[2m'; C_BLD=$'\033[1m'; C_OFF=$'\033[0m'
    if [ "$(tput colors 2>/dev/null || echo 8)" -ge 256 ]; then UI_256=1; fi
    COLS="$(tput cols 2>/dev/null || echo 70)"
    if [ "$COLS" -gt 72 ]; then COLS=72; fi
    if [ "$COLS" -lt 40 ]; then COLS=40; fi
    if [ "$FAST" -eq 0 ] && [ "$NON_INTERACTIVE" -eq 0 ]; then SLOW=1; fi
  fi
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*)
      UI_UTF8=1; SYM_OK="✔"; SYM_BAD="✖"; SYM_WARN="!"; SYM_DOT="•"; RULE_CH="─" ;;
  esac
}

nap() {
  if [ "$SLOW" -eq 1 ]; then sleep "$1"; fi
  return 0
}

rule() {
  local line="" i
  for ((i = 0; i < COLS; i++)); do line+="$RULE_CH"; done
  printf '%s%s%s\n' "$C_DIM" "$line" "$C_OFF"
}

info() { printf '  %s%s%s %s\n' "$C_DIM" "$SYM_DOT" "$C_OFF" "$*"; }
ok()   { printf '  %s%s%s %s\n' "$C_GRN" "$SYM_OK" "$C_OFF" "$*"; nap 0.35; }
bad()  { printf '  %s%s%s %s\n' "$C_RED" "$SYM_BAD" "$C_OFF" "$*"; nap 0.35; }
warn() { printf '  %s%s%s %s\n' "$C_YLW" "$SYM_WARN" "$C_OFF" "$*" >&2; }
die()  { printf '\n  %s%s %s%s\n\n' "$C_RED" "$SYM_BAD" "$*" "$C_OFF" >&2; exit 1; }

step() {  # step N TOTAL "Title"
  nap 0.5
  printf '\n'
  rule
  nap 0.2
  printf ' %sStep %s/%s%s  %s%s%s\n' "$C_CYN" "$1" "$2" "$C_OFF" "$C_BLD" "$3" "$C_OFF"
  nap 0.2
  rule
  nap 0.4
}

paint() {  # paint LINE ROW
  if [ "$UI_COLOR" -eq 0 ]; then printf '%s\n' "$1"; return; fi
  if [ "$UI_256" -eq 1 ]; then
    local shades=(51 45 39 33 27 21)
    printf '\033[38;5;%sm%s\033[0m\n' "${shades[$2]}" "$1"
  else
    printf '%s%s%s\n' "$C_CYN" "$1" "$C_OFF"
  fi
  nap 0.12
}

banner() {
  if [ "$UI_UTF8" -eq 1 ] && [ "$COLS" -ge 64 ]; then
    local -a art=(
      '██████╗ ██████╗ ██╗██╗   ██╗ █████╗ ████████╗███████╗'
      '██╔══██╗██╔══██╗██║██║   ██║██╔══██╗╚══██╔══╝██╔════╝'
      '██████╔╝██████╔╝██║██║   ██║███████║   ██║   █████╗  '
      '██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══██║   ██║   ██╔══╝  '
      '██║     ██║  ██║██║ ╚████╔╝ ██║  ██║   ██║   ███████╗'
      '╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝   ╚═╝   ╚══════╝'
      '████████╗ ██████╗  ██████╗ ██╗     ██████╗  ██████╗ ██╗  ██╗'
      '╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔══██╗██╔═══██╗╚██╗██╔╝'
      '   ██║   ██║   ██║██║   ██║██║     ██████╔╝██║   ██║ ╚███╔╝ '
      '   ██║   ██║   ██║██║   ██║██║     ██╔══██╗██║   ██║ ██╔██╗ '
      '   ██║   ╚██████╔╝╚██████╔╝███████╗██████╔╝╚██████╔╝██╔╝ ██╗'
      '   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝'
    )
    local i
    for i in "${!art[@]}"; do paint "  ${art[$i]}" "$((i % 6))"; done
  else
    printf '\n  %s== PRIVATE TOOLBOX ==%s\n' "$C_CYN" "$C_OFF"
  fi
  nap 0.4
  printf '\n  %sPrivateToolBox (Private Tool)%s  %s|  v%s%s\n' "$C_BLD" "$C_OFF" "$C_DIM" "$PT_VERSION" "$C_OFF"
  nap 0.35
  printf '  Safe hardening and tuning for your Linux server\n'
  nap 0.35
  printf '  %sGitHub:%s Sorena-max  %s|%s  github.com/%s\n' "$C_BLD" "$C_OFF" "$C_DIM" "$C_OFF" "$REPO_SLUG"
  nap 0.35
  printf '  %sThis project is completely free. Selling it or charging money for it is prohibited.%s\n' "$C_YLW" "$C_OFF"
}

show_header() {
  if [ "$UI_COLOR" -eq 1 ] && [ "$NO_CLEAR" -eq 0 ]; then printf '\033[2J\033[H'; fi
  printf '\n'
  nap 0.3
  banner
  nap 1
}

cleanup() { [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"; return 0; }
trap cleanup EXIT

usage() {
  cat <<'EOF'
PrivateToolBox installer

Usage: install.sh [install|update|uninstall] [options]

Options:
  --ref REF           git branch or tag to install (default: main)
  --purge              with uninstall: also delete history and settings
  --no-clear           do not clear the screen at the start
  --fast               no animation or pauses (the default when not run by a person)
  --non-interactive    never prompt
  --local-source DIR   install from a local checkout (development / CI)
  -h, --help           show this help

Piped install with flags:  curl -fsSL <url> | sudo bash -s -- --non-interactive
EOF
}

parse_args() {
  if [ $# -gt 0 ]; then
    case "$1" in install|update|uninstall) COMMAND="$1"; shift ;; esac
  fi
  while [ $# -gt 0 ]; do
    case "$1" in
      --ref) REF="${2:?--ref needs a value}"; shift 2 ;;
      --local-source) LOCAL_SOURCE="${2:?--local-source needs a value}"; shift 2 ;;
      --non-interactive|--yes|-y) NON_INTERACTIVE=1; shift ;;
      --purge) PURGE=1; shift ;;
      --no-clear) NO_CLEAR=1; shift ;;
      --fast) FAST=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done
}

need_root() {
  [ "$(id -u)" -eq 0 ] || die "please run as root, e.g.: curl -fsSL <url> | sudo bash"
}

os_name() {
  local name=""
  if [ -r /etc/os-release ]; then
    name="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-}")"
  fi
  printf '%s' "${name:-Linux}"
}

detect_pm() {
  local cand
  for cand in apt-get dnf yum zypper pacman; do
    if command -v "$cand" >/dev/null 2>&1; then PM="$cand"; return; fi
  done
  PM=""
}

pkg_name() {
  case "$PM:$1" in
    pacman:python3) echo python ;;
    *) echo "$1" ;;
  esac
}

pkg_install() {
  [ -n "$PM" ] || die "cannot install $* automatically: no supported package manager found"
  local pkgs=() p
  for p in "$@"; do pkgs+=("$(pkg_name "$p")"); done
  info "installing missing packages: ${pkgs[*]}"
  case "$PM" in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get update -qq </dev/null
             DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" </dev/null ;;
    dnf)     dnf install -y -q "${pkgs[@]}" </dev/null ;;
    yum)     yum install -y -q "${pkgs[@]}" </dev/null ;;
    zypper)  zypper --non-interactive install -y "${pkgs[@]}" </dev/null ;;
    pacman)  pacman -Sy --noconfirm --needed "${pkgs[@]}" </dev/null ;;
  esac
}

ensure_prereqs() {
  local missing=()
  command -v python3 >/dev/null 2>&1 || missing+=(python3)
  command -v curl >/dev/null 2>&1 || missing+=(curl)
  command -v tar >/dev/null 2>&1 || missing+=(tar)
  [ -e /etc/ssl/certs ] || missing+=(ca-certificates)
  if [ ${#missing[@]} -gt 0 ]; then
    pkg_install "${missing[@]}"
  fi
  python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" \
    || die "Python $MIN_PY or newer is required (found $(python3 -V 2>&1))"
  ok "python3 ($(python3 -V 2>&1 | cut -d' ' -f2)), curl and tar are ready"
}

have_tty() { (exec </dev/tty) 2>/dev/null; }

prompt() {  # prompt VAR "text"
  local __var="$1" __value=""
  read -rp "$2" __value </dev/tty
  printf -v "$__var" '%s' "$__value"
}

checker_active() {
  command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet privatechecker 2>/dev/null
}

offer_bridge() {
  checker_active || return 0
  printf '\n  %sPrivateChecker is running on this server.%s\n' "$C_BLD" "$C_OFF"
  info "PrivateToolBox can also be used from inside your Telegram bot (owner only)."
  if [ "$NON_INTERACTIVE" -eq 1 ] || ! have_tty; then
    info "To enable it later: sudo privatetoolbox integrate"
    return 0
  fi
  local answer
  prompt answer "  Add the PrivateToolBox button to your PrivateChecker bot? [y/N] "
  case "$answer" in
    y|Y|yes|YES) "$BIN_FILE" integrate --yes || warn "could not enable it, try: sudo privatetoolbox integrate" ;;
    *) info "Skipped. Enable it any time with: sudo privatetoolbox integrate" ;;
  esac
}

fetch_source() {
  if [ -n "$LOCAL_SOURCE" ]; then
    SRC="$(cd "$LOCAL_SOURCE" && pwd)"
  else
    TMP_DIR="$(mktemp -d)"
    working "Downloading PrivateToolBox ($REF) from GitHub"
    curl -fsSL --retry 3 --connect-timeout 15 \
      "https://github.com/$REPO_SLUG/archive/$REF.tar.gz" -o "$TMP_DIR/src.tar.gz" \
      || { done_working; die "download failed - check your connection and that '$REF' exists"; }
    tar -xzf "$TMP_DIR/src.tar.gz" -C "$TMP_DIR"
    SRC="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1 || true)"
    done_working
  fi
  [ -d "${SRC:-}/privatetoolbox" ] || die "PrivateToolBox sources not found in the download"
  ok "Downloaded PrivateToolBox ($REF)"
}

working() { if [ "$UI_COLOR" -eq 1 ]; then printf '  %s...%s %s' "$C_DIM" "$C_OFF" "$1"; fi; }
done_working() { if [ "$UI_COLOR" -eq 1 ]; then printf '\r\033[K'; fi; }

deploy() {
  install -d -m 755 "$APP_DIR"
  rm -rf "$APP_DIR/privatetoolbox"
  cp -a "$SRC/privatetoolbox" "$APP_DIR/privatetoolbox"
  cp "$SRC/install.sh" "$APP_DIR/install.sh"
  chmod 755 "$APP_DIR/install.sh"
  find "$APP_DIR" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
  chown -R root:root "$APP_DIR"
  install -d -m 700 "$STATE_DIR"
  ok "Files installed in $APP_DIR ${C_DIM}(owned by root)${C_OFF}"
}

write_cli() {
  cat >"$BIN_FILE" <<'EOF'
#!/usr/bin/env bash
# privatetoolbox - hardening and tuning for this server
case "${1:-}" in
  update)    shift; exec bash /opt/privatetoolbox/install.sh update "$@" ;;
  uninstall) shift; exec bash /opt/privatetoolbox/install.sh uninstall "$@" ;;
esac
export PYTHONPATH=/opt/privatetoolbox PYTHONDONTWRITEBYTECODE=1
exec python3 -m privatetoolbox "$@"
EOF
  chmod 755 "$BIN_FILE"
  ok "Command added: privatetoolbox"
}

finish_screen() {
  printf '\n'
  rule
  printf ' %s%s PrivateToolBox is installed%s\n' "$C_GRN" "$SYM_OK" "$C_OFF"
  rule
  printf '\n  %s1.%s Look at your server first (changes nothing):\n' "$C_BLD" "$C_OFF"
  printf '       sudo privatetoolbox scan\n'
  printf '  %s2.%s Open the menu:\n' "$C_BLD" "$C_OFF"
  printf '       sudo privatetoolbox\n'
  printf '  %s3.%s Or apply the recommended set (shows the plan, asks first, and rolls back by itself):\n' "$C_BLD" "$C_OFF"
  printf '       sudo privatetoolbox apply --profile recommended\n'
  printf '\n  %sGitHub: Sorena-max  |  https://github.com/%s%s\n' "$C_DIM" "$REPO_SLUG" "$C_OFF"
  printf '  %sFree software - selling it or charging for it is prohibited.%s\n\n' "$C_DIM" "$C_OFF"
}

do_install() {
  need_root
  detect_pm

  step 1 4 "Checking this server"
  ok "$(os_name) ${C_DIM}|${C_OFF} running as root"
  ensure_prereqs

  step 2 4 "Downloading"
  fetch_source

  step 3 4 "Installing"
  deploy
  write_cli

  step 4 4 "Ready"
  finish_screen
  offer_bridge
}

do_uninstall() {
  need_root
  step 1 1 "Removing PrivateToolBox"
  rm -f "$BIN_FILE"
  rm -rf "$APP_DIR"
  if [ "$PURGE" -eq 1 ]; then
    rm -rf "$STATE_DIR"
    ok "Removed everything, including history and settings"
  else
    ok "Removed the program ${C_DIM}(history kept in $STATE_DIR; use --purge to delete)${C_OFF}"
  fi
  warn "Changes made to your server (firewall, SSH, sysctl ...) stay. Run 'privatetoolbox undo' before uninstalling to take them back."
  printf '\n'
}

main() {
  parse_args "$@"
  setup_ui
  show_header
  case "$COMMAND" in
    install|update) do_install ;;
    uninstall) do_uninstall ;;
  esac
}

main "$@"

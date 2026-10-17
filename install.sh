#!/usr/bin/env bash
# rectool installer for Linux (Debian/Ubuntu/Kali, Fedora/RHEL, Arch, openSUSE, Alpine).
#
#   ./install.sh                 system-wide install (uses sudo if not root)
#   ./install.sh --user          install into ~/.local (no root needed)
#   ./install.sh --uninstall     remove what this script installed
#
# What it does: installs build/runtime dependencies, installs Go >= 1.22 if
# missing, builds rectool from this directory, installs the binary, downloads
# the 600+ site WhatsMyName list, and installs the optional external tools
# (whois, dig, sherlock, theHarvester) that the syswrap module can wrap.

set -Eeuo pipefail

# ---------------------------------------------------------------- settings --
GO_MIN_MINOR=22
WMN_URL="https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE=""            # system | user (auto-detected unless forced)
PREFIX=""          # override install prefix (bin/ and share/rectool/ go under it)
DO_DEPS=1 DO_EXTRAS=1 DO_SITES=1 DO_UNINSTALL=0
SUDO=""
PM=""
TMP=""
DIED=0

# ------------------------------------------------------------------ output --
if [[ -t 1 ]]; then B=$'\e[1m' G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' N=$'\e[0m'; else B="" G="" Y="" R="" N=""; fi
info() { printf '%s[*]%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[!]%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { DIED=1; printf '%s[x]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

trap 'rc=$?; [[ -n "$TMP" ]] && rm -rf "$TMP"; [[ $rc -ne 0 && $DIED -eq 0 ]] && printf "%s[x]%s install failed (line %s, exit %s)\n" "$R" "$N" "${BASH_LINENO[0]}" "$rc" >&2; exit $rc' EXIT

usage() {
  sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options:
  --user            install for the current user only (~/.local)
  --system          force system-wide install (/usr/local)
  --prefix DIR      custom prefix (binary in DIR/bin, data in DIR/share/rectool)
  --no-deps         skip OS package installation
  --no-extras       skip whois/dig/sherlock/theHarvester
  --no-sites        skip downloading the WhatsMyName site list
  --uninstall       remove rectool binary and data
  -h, --help        show this help
EOF
}

# -------------------------------------------------------------- arguments --
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) MODE=user ;;
    --system) MODE=system ;;
    --prefix) PREFIX="${2:?--prefix needs a directory}"; shift ;;
    --no-deps) DO_DEPS=0 ;;
    --no-extras) DO_EXTRAS=0 ;;
    --no-sites) DO_SITES=0 ;;
    --uninstall) DO_UNINSTALL=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
  shift
done

[[ "$(uname -s)" == "Linux" ]] || die "this installer is for Linux only (detected $(uname -s))"

# ------------------------------------------------------------ mode / paths --
if [[ -z "$MODE" ]]; then
  if [[ $EUID -eq 0 || -n "$PREFIX" && -w "$PREFIX" ]] || have sudo; then MODE=system; else MODE=user; fi
fi
if [[ "$MODE" == system && $EUID -ne 0 && -z "$PREFIX" ]]; then
  if have sudo; then SUDO="sudo"; else warn "no root and no sudo: falling back to --user"; MODE=user; fi
fi
if [[ -n "$PREFIX" && "$MODE" == system && $EUID -ne 0 && ! -w "$PREFIX" ]] && have sudo; then SUDO="sudo"; fi

if [[ -n "$PREFIX" ]]; then
  BIN_DIR="$PREFIX/bin"; DATA_DIR="$PREFIX/share/rectool"
elif [[ "$MODE" == system ]]; then
  BIN_DIR=/usr/local/bin; DATA_DIR=/usr/local/share/rectool
else
  BIN_DIR="$HOME/.local/bin"; DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/rectool"
fi
if [[ "$MODE" == system ]]; then GO_ROOT=/usr/local/go; else GO_ROOT="$HOME/.local/go"; fi
if [[ -n "$PREFIX" ]]; then GO_ROOT="$PREFIX/go"; fi
# Package installs need root regardless of the install mode.
PSUDO=""; CAN_PKG=1
if [[ $EUID -ne 0 ]]; then if have sudo; then PSUDO="sudo"; else CAN_PKG=0; fi; fi
# Privileged commands only when the target is system-owned.
PRIV="$SUDO"; [[ "$MODE" == user && -z "$PREFIX" ]] && PRIV=""

# --------------------------------------------------------------- uninstall --
if [[ $DO_UNINSTALL -eq 1 ]]; then
  info "removing $BIN_DIR/rectool and $DATA_DIR"
  $PRIV rm -f "$BIN_DIR/rectool"
  $PRIV rm -rf "$DATA_DIR"
  ok "removed. (Go, OS packages and pipx tools were left untouched.)"
  exit 0
fi

# -------------------------------------------------------- package managers --
detect_pm() {
  for p in apt-get dnf yum pacman zypper apk; do have "$p" && { PM="$p"; return; }; done
  PM=""
}

pm_refresh() {
  case "$PM" in
    apt-get) $PSUDO apt-get update -qq ;;
    pacman)  $PSUDO pacman -Sy --noconfirm >/dev/null ;;
    zypper)  $PSUDO zypper --non-interactive refresh >/dev/null ;;
  esac
}

# pm_install PKG: install one package; returns non-zero if unavailable.
pm_install() {
  case "$PM" in
    apt-get) $PSUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$1" >/dev/null ;;
    dnf)     $PSUDO dnf install -y -q "$1" >/dev/null ;;
    yum)     $PSUDO yum install -y -q "$1" >/dev/null ;;
    pacman)  $PSUDO pacman -S --noconfirm --needed "$1" >/dev/null ;;
    zypper)  $PSUDO zypper --non-interactive install "$1" >/dev/null ;;
    apk)     $PSUDO apk add --quiet "$1" >/dev/null ;;
    *)       return 1 ;;
  esac
}

# Package names differ per distro family.
pkg_names() { # echo package list for role $1
  case "$1:$PM" in
    base:*)            echo "curl ca-certificates tar gzip git" ;;
    whois:*)           echo "whois" ;;
    dig:apt-get)       echo "dnsutils" ;;
    dig:dnf|dig:yum|dig:zypper) echo "bind-utils" ;;
    dig:pacman)        echo "bind" ;;
    dig:apk)           echo "bind-tools" ;;
    pipx:apt-get)      echo "pipx python3-venv" ;;
    pipx:dnf|pipx:yum) echo "pipx" ;;
    pipx:pacman)       echo "python-pipx" ;;
    pipx:zypper)       echo "python3-pipx" ;;
    pipx:apk)          echo "pipx" ;;
  esac
}

install_roles() { # install_roles required|optional role...
  local level="$1"; shift
  local role pkg
  for role in "$@"; do
    for pkg in $(pkg_names "$role"); do
      if pm_install "$pkg"; then continue; fi
      if [[ "$level" == required ]]; then die "could not install required package: $pkg"; fi
      warn "optional package unavailable: $pkg"
    done
  done
}

# ---------------------------------------------------------------------- Go --
go_ok() { # go_ok BIN : is that go >= 1.$GO_MIN_MINOR ?
  local v minor major
  v="$("$1" env GOVERSION 2>/dev/null || true)"; v="${v#go}"
  major="${v%%.*}"; minor="${v#*.}"; minor="${minor%%[!0-9]*}"
  [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
  (( major > 1 || (major == 1 && minor >= GO_MIN_MINOR) ))
}

install_go() {
  local arch ver file url want got
  case "$(uname -m)" in
    x86_64|amd64)  arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    armv7l|armv6l) arch=armv6l ;;
    i386|i686)     arch=386 ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
  esac
  ver="$(curl -fsSL "https://go.dev/VERSION?m=text" | head -n1)"
  [[ "$ver" =~ ^go1\.[0-9]+ ]] || die "could not determine latest Go version"
  file="${ver}.linux-${arch}.tar.gz"
  info "downloading Go ${ver#go} (${arch})"
  curl -fSL --retry 3 -o "$TMP/$file" "https://go.dev/dl/$file"
  want="$(curl -fsSL "https://dl.google.com/go/$file.sha256" | tr -d '[:space:]')"
  got="$(sha256sum "$TMP/$file" | cut -d' ' -f1)"
  [[ -n "$want" && "$want" == "$got" ]] || die "Go archive checksum mismatch (expected '$want', got '$got')"
  info "installing Go into $GO_ROOT"
  local parent; parent="$(dirname "$GO_ROOT")"
  if [[ "$MODE" == system ]]; then $SUDO rm -rf "$GO_ROOT"; $SUDO tar -C "$parent" -xzf "$TMP/$file"
  else mkdir -p "$parent"; rm -rf "$GO_ROOT"; tar -C "$parent" -xzf "$TMP/$file"; fi
}

ensure_go() {
  local c
  for c in "$(command -v go 2>/dev/null || true)" "$GO_ROOT/bin/go" /usr/local/go/bin/go "$HOME/.local/go/bin/go"; do
    if [[ -n "$c" && -x "$c" ]] && go_ok "$c"; then GO_BIN="$c"; ok "using $("$c" version)"; return; fi
  done
  info "Go >= 1.$GO_MIN_MINOR not found"
  install_go
  GO_BIN="$GO_ROOT/bin/go"
  go_ok "$GO_BIN" || die "Go installation failed"
  ok "installed $("$GO_BIN" version)"
}

# ------------------------------------------------------------------- build --
build_rectool() {
  [[ -f "$SRC_DIR/go.mod" && -d "$SRC_DIR/cmd/rectool" ]] || die "run install.sh from the rectool source directory"
  info "building rectool"
  ( cd "$SRC_DIR"
    export PATH="$(dirname "$GO_BIN"):$PATH" CGO_ENABLED=0 GOFLAGS=-trimpath
    "$GO_BIN" mod tidy
    "$GO_BIN" build -ldflags "-s -w" -o "$TMP/rectool" ./cmd/rectool )
  ok "build complete"
}

install_files() {
  info "installing to $BIN_DIR and $DATA_DIR"
  $PRIV install -d -m 0755 "$BIN_DIR" "$DATA_DIR"
  $PRIV install -m 0755 "$TMP/rectool" "$BIN_DIR/rectool"
  if [[ -d "$SRC_DIR/configs" ]]; then $PRIV cp -r "$SRC_DIR/configs/." "$DATA_DIR/" ; fi
  ok "installed $BIN_DIR/rectool"
}

fetch_sites() {
  info "downloading WhatsMyName site list (600+ platforms)"
  if curl -fsSL --retry 3 -o "$TMP/wmn.json" "$WMN_URL" && grep -q '"sites"' "$TMP/wmn.json"; then
    $PRIV install -m 0644 "$TMP/wmn.json" "$DATA_DIR/wmn-data.json"
    ok "site list saved to $DATA_DIR/wmn-data.json (rectool picks it up automatically)"
  else
    warn "could not download the site list; rectool will use its small built-in list"
  fi
}

# ------------------------------------------------------------------ extras --
pipx_run() { # pipx_run ARGS... : pipx with a system-wide home in system mode
  if [[ "$MODE" == system ]]; then
    $PSUDO env PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx "$@"
  else
    pipx "$@"
  fi
}

install_extras() {
  info "installing optional external tools"
  have whois || install_roles optional whois
  have dig   || install_roles optional dig
  have pipx  || install_roles optional pipx

  if have pipx; then
    local tool pkg
    for tool in sherlock:sherlock-project maigret:maigret holehe:holehe; do
      pkg="${tool#*:}"; tool="${tool%%:*}"
      if have "$tool"; then ok "$tool already installed"
      elif pipx_run install "$pkg" >/dev/null 2>&1; then ok "installed $tool"
      else warn "could not install $tool (try: pipx install $pkg)"; fi
    done
  else
    warn "pipx unavailable: skipping sherlock"
  fi

  if have theHarvester || have theharvester; then ok "theHarvester already installed"
  elif [[ "$PM" == apt-get ]] && pm_install theharvester 2>/dev/null; then ok "installed theHarvester"
  else warn "theHarvester not installed (install manually: https://github.com/laramies/theHarvester)"; fi

  if have whatweb; then ok "whatweb already installed"
  elif pm_install whatweb 2>/dev/null; then ok "installed whatweb"
  else warn "whatweb not available from the package manager (optional)"; fi

  if have subfinder; then ok "subfinder already installed"
  elif [[ -n "${GO_BIN:-}" ]]; then
    info "installing subfinder with go install (optional, may take a minute)"
    if PATH="$(dirname "$GO_BIN"):$PATH" GOBIN="$TMP/gobin" "$GO_BIN" install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest >/dev/null 2>&1 \
       && $PRIV install -m 0755 "$TMP/gobin/subfinder" "$BIN_DIR/subfinder"; then ok "installed subfinder"
    else warn "could not install subfinder (optional: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)"; fi
  fi
}

# --------------------------------------------------------------------- run --
main() {
  TMP="$(mktemp -d)"
  info "mode: $MODE   binary: $BIN_DIR/rectool   data: $DATA_DIR"

  if [[ $DO_DEPS -eq 1 ]]; then
    detect_pm
    if [[ -z "$PM" ]]; then warn "no supported package manager found; assuming curl/tar/git are present"
    else
      if [[ $CAN_PKG -eq 0 ]]; then warn "no root/sudo: skipping OS packages"; PM=""; fi
      if [[ -n "$PM" ]]; then
        info "package manager: $PM"
        pm_refresh
        install_roles required base
      fi
    fi
  else
    detect_pm
  fi
  have curl || die "curl is required"

  ensure_go
  build_rectool
  install_files
  [[ $DO_SITES -eq 1 ]] && fetch_sites
  [[ $DO_EXTRAS -eq 1 && $DO_DEPS -eq 1 && -n "$PM" ]] && install_extras

  # ---- verify
  local bin="$BIN_DIR/rectool"
  "$bin" -version >/dev/null || die "installed binary does not run"
  ok "$("$bin" -version)"
  "$bin" -list-modules | sed 's/^/    /'

  echo
  ok "done."
  if ! echo ":$PATH:" | grep -q ":$BIN_DIR:"; then
    warn "$BIN_DIR is not in your PATH. Add it with:"
    echo "      echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
  fi
  cat <<EOF

Try it:
  rectool -u johndoe -verify -o reports
  rectool -n "Jane Doe" -e jane@example.com -derive -o reports
  rectool -web 127.0.0.1:8080     # browser UI (prints a URL with your access token)
  rectool -h

Use only on subjects you are lawfully permitted to investigate.
EOF
}

main "$@"

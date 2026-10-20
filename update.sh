#!/usr/bin/env bash
# rectool updater: pulls the latest source, rebuilds and reinstalls.
#
#   ./update.sh                  update using the same install mode as before
#   ./update.sh --user           (any other option is passed on to install.sh)
#   ./update.sh --check          only report whether a newer version exists
#
# Your reports, proxies lists and custom site files are not touched.

set -Eeuo pipefail
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SRC_DIR"

B=$'\e[1m' G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' N=$'\e[0m'
info() { printf '%s[*]%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[!]%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

command -v git >/dev/null 2>&1 || die "git is required (apt install git / dnf install git / pacman -S git)"
[[ -d .git ]] || die "$SRC_DIR is not a git checkout. Re-clone with: git clone https://github.com/sudosoc/rectool"

CHECK=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --check) CHECK=1 ;;
    -h|--help) sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) ARGS+=("$a") ;;
  esac
done

old="$(git rev-parse --short HEAD)"
info "current version: $old ($(git log -1 --format=%cs))"
info "fetching updates..."
git fetch --quiet origin
branch="$(git rev-parse --abbrev-ref HEAD)"
behind="$(git rev-list --count "HEAD..origin/$branch" 2>/dev/null || echo 0)"

if [[ "$behind" -eq 0 ]]; then
  ok "already up to date"
  [[ $CHECK -eq 1 ]] && exit 0
  info "rebuilding anyway (use Ctrl-C to skip)"
else
  info "$behind new commit(s):"
  git --no-pager log --oneline "HEAD..origin/$branch" | head -20
  [[ $CHECK -eq 1 ]] && exit 0
  if ! git diff --quiet || ! git diff --cached --quiet; then
    warn "you have local changes; stashing them for the update"
    git stash push --quiet -m "rectool update $(date +%F-%H%M)"
    STASHED=1
  fi
  git pull --ff-only --quiet origin "$branch" || die "cannot fast-forward; resolve manually with: git pull"
  [[ "${STASHED:-0}" -eq 1 ]] && { git stash pop --quiet || warn "stash pop conflicted; your changes are in 'git stash list'"; }
fi

info "rebuilding and reinstalling (OS packages are skipped; run ./install.sh for those)..."
bash ./install.sh --no-deps "${ARGS[@]}"
ok "updated $old -> $(git rev-parse --short HEAD)"

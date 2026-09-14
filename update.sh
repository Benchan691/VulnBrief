#!/usr/bin/env bash
#
# VulnBrief update: pull the latest code and rebuild/restart the Docker service.
#
# Data (MongoDB, ./newsletters, .env) is untouched; the app re-creates its
# MongoDB indexes on startup, so no manual migration step is needed.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

ASSUME_YES=0
DEFAULT_PORT=9100

# --- output helpers ---------------------------------------------------------

if [[ -t 1 ]]; then
  C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'
  C_INFO=$'\033[36m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_INFO=""; C_BOLD=""; C_DIM=""; C_OFF=""
fi

info() { printf '%s\n' "${C_INFO}==>${C_OFF} $*"; }
ok()   { printf '%s\n' "  ${C_OK}*${C_OFF} $*"; }
warn() { printf '%s\n' "  ${C_WARN}!${C_OFF} $*" >&2; }
die()  { printf '%s\n' "${C_ERR}Error:${C_OFF} $*" >&2; exit 1; }

confirm() { # confirm <message> [default y|n]
  local msg="$1" def="${2:-y}" reply
  if (( ASSUME_YES )); then
    info "$msg — assumed yes (--yes)"
    return 0
  fi
  if [[ "$def" == "y" ]]; then
    read -r -p "$msg [Y/n] " reply || die "Aborted."
  else
    read -r -p "$msg [y/N] " reply || die "Aborted."
  fi
  reply="${reply:-$def}"
  [[ "$reply" =~ ^[Yy] ]]
}

# --- small utilities --------------------------------------------------------

port_open() { (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null; }

env_value() { # env_value <key> <default>
  local line
  line="$(grep -E "^$1=" .env 2>/dev/null | tail -n 1 | cut -d= -f2-)"
  printf '%s' "${line:-$2}" | tr -d '"'"'"
}

wait_for_web() { # wait_for_web <port> — any HTTP answer counts as alive
  local port="$1" i code
  for i in $(seq 1 45); do
    if command -v curl >/dev/null 2>&1; then
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:${port}/" 2>/dev/null || true)"
      [[ -n "$code" && "$code" != "000" ]] && return 0
    else
      port_open 127.0.0.1 "$port" && return 0
    fi
    sleep 2
  done
  return 1
}

# --- docker -----------------------------------------------------------------

COMPOSE=()
detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    return 1
  fi
}

usage() {
  cat <<'EOF'
VulnBrief update

Usage: ./update.sh [-y|--yes] [-h|--help]

  -y, --yes   Assume yes for all confirmations (non-interactive)
  -h, --help  Show this help

Pulls the latest code with git, rebuilds the image, and restarts the
container. MongoDB data, ./newsletters and .env are left untouched.
EOF
}

# --- main -------------------------------------------------------------------

while (("$#")); do
  case "$1" in
    -y|--yes) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (try --help)" ;;
  esac
done

command -v git >/dev/null 2>&1 || die "git is required."
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "Not inside a git repository (run this script from a VulnBrief checkout)."
[[ -f .env ]] || die "No .env found. Run ./setup.sh first."
command -v docker >/dev/null 2>&1 || die "Docker is required. Install it from https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || die "Docker daemon is not running. Start Docker and try again."
detect_compose || die "Docker Compose is required (docker compose plugin or docker-compose)."

OLD_HEAD="$(git rev-parse --short HEAD)"

# Warn about local modifications to tracked files (untracked files such as
# newsletters/*.html, .env and certs are safe and left alone).
DIRTY="$(git status --porcelain | grep -v '^??' || true)"
if [[ -n "$DIRTY" ]]; then
  warn "You have local modifications to tracked files:"
  printf '%s\n' "$DIRTY" | sed 's/^/    /'
  warn "git pull may fail if the update touches the same files."
  confirm "Continue?" "n" || die "Aborted."
fi

# Figure out where to pull from.
UPSTREAM="$(git rev-parse --abbrev-ref '@{u}' 2>/dev/null || true)"
if [[ -n "$UPSTREAM" ]]; then
  REMOTE="${UPSTREAM%%/*}"
  BRANCH="${UPSTREAM#*/}"
else
  REMOTE="origin"
  BRANCH="$(git symbolic-ref --short HEAD 2>/dev/null || echo main)"
fi

info "Fetching latest changes from $REMOTE..."
SKIP_PULL=0
if ! git fetch "$REMOTE" --quiet; then
  warn "Could not reach $REMOTE (offline?)."
  confirm "Continue without pulling updates (just rebuild/restart)?" "n" || die "Aborted."
  SKIP_PULL=1
fi

BEHIND=0
if (( ! SKIP_PULL )); then
  BEHIND="$(git rev-list --count "HEAD..$REMOTE/$BRANCH" 2>/dev/null || echo 0)"
  if (( BEHIND > 0 )); then
    info "$BEHIND new commit(s) available:"
    git log --oneline --no-decorate "HEAD..$REMOTE/$BRANCH"
    confirm "Apply the update?" "y" || die "Aborted."
    info "Pulling updates..."
    git pull --ff-only "$REMOTE" "$BRANCH" || die "git pull failed. Resolve local changes manually (e.g. git stash) and re-run ./update.sh."
    ok "Updated to $(git rev-parse --short HEAD)."
  else
    info "Already up to date with $REMOTE/$BRANCH."
    confirm "Rebuild and restart anyway?" "n" || exit 0
  fi
fi

info "Rebuilding and restarting VulnBrief..."
"${COMPOSE[@]}" up -d --build || die "docker compose up failed."

PORT="$(env_value WEB_PORT "$DEFAULT_PORT")"
[[ "$PORT" =~ ^[0-9]+$ ]] || PORT="$DEFAULT_PORT"
info "Waiting for the web app to answer on port $PORT..."
if wait_for_web "$PORT"; then
  ok "VulnBrief is up."
else
  warn "The app did not answer on port $PORT within 90 seconds. Last log lines:"
  "${COMPOSE[@]}" logs --tail=50 web || true
  die "Update could not confirm the app is healthy. Check the logs above."
fi

NEW_HEAD="$(git rev-parse --short HEAD)"
echo
printf '%s\n' "${C_OK}${C_BOLD:-}Update complete!${C_OFF}"
if [[ "$OLD_HEAD" != "$NEW_HEAD" ]]; then
  printf '%s\n' "  Code:      $OLD_HEAD -> $NEW_HEAD"
else
  printf '%s\n' "  Code:      $NEW_HEAD (rebuilt)"
fi
printf '%s\n' "  Web UI:    http://localhost:$PORT"
printf '%s\n' "  Data kept: MongoDB, ./newsletters, .env (no manual migrations needed)"
printf '%s\n' "  Logs:      ${COMPOSE[*]} logs -f web"

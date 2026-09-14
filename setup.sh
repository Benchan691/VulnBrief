#!/usr/bin/env bash
#
# VulnBrief interactive setup (Docker).
#
# Walks through configuration (.env), makes sure MongoDB is reachable,
# then builds and starts the app with Docker Compose.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

DEFAULT_PORT=9100
MONGO_CONTAINER=webserver-local-mongo
MONGO_VOLUME=webserver-local-mongo-data

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

# --- prompting helpers ------------------------------------------------------

confirm() { # confirm <message> [default y|n]
  local msg="$1" def="${2:-y}" reply
  if [[ "$def" == "y" ]]; then
    read -r -p "$msg [Y/n] " reply || die "Aborted."
  else
    read -r -p "$msg [y/N] " reply || die "Aborted."
  fi
  reply="${reply:-$def}"
  [[ "$reply" =~ ^[Yy] ]]
}

prompt_value() { # prompt_value <label> [default]
  local label="$1" def="${2:-}" reply
  read -r -e -p "$label${def:+ [$def]}: " reply || die "Aborted."
  printf '%s' "${reply:-$def}"
}

prompt_secret() { # prompt_secret <label> [default]
  local label="$1" def="${2:-}" reply
  read -rs -p "$label${def:+ [enter = keep default]}: " reply || die "Aborted."
  printf '\n'
  printf '%s' "${reply:-$def}"
}

# --- small utilities --------------------------------------------------------

port_open() { (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null; }

generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    tr -dc 'a-f0-9' < /dev/urandom | head -c 64
  fi
}

env_value() { # env_value <key> <default>
  local line
  line="$(grep -E "^$1=" .env 2>/dev/null | tail -n 1 | cut -d= -f2-)"
  printf '%s' "${line:-$2}" | tr -d '"'"'"
}

set_env_var() { # set_env_var <file> <key> <value>
  local file="$1" key="$2" value="$3" tmp
  tmp="$file.tmp.$$"
  ENVKEY="$key" ENVVAL="$value" awk '
    BEGIN { key = ENVIRON["ENVKEY"]; val = ENVIRON["ENVVAL"]; needle = key "=" }
    index($0, needle) == 1 { print key "=" val; found = 1; next }
    { print }
    END { if (!found) print key "=" val }
  ' "$file" > "$tmp" && mv "$tmp" "$file"
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

# Parse mongodb://[user:pass@]host[:port][/...] into MONGO_HOST / MONGO_PORT.
# Returns 1 for mongodb+srv URIs or anything unparseable.
parse_mongo_target() {
  local uri="$1" rest host port
  case "$uri" in
    mongodb://*) : ;;
    *) return 1 ;;
  esac
  rest="${uri#*://}"
  rest="${rest%%\?*}"
  rest="${rest%%/*}"
  rest="${rest##*@}"
  if [[ "$rest" == \[* ]]; then
    host="${rest%%]*}"; host="${host#\[}"
    if [[ "$rest" == *\]:* ]]; then port="${rest##*]:}"; else port=27017; fi
  else
    host="${rest%%:*}"
    if [[ "$rest" == *:* ]]; then port="${rest##*:}"; else port=27017; fi
  fi
  [[ -n "$host" && "$port" =~ ^[0-9]+$ ]] || return 1
  MONGO_HOST="$host"; MONGO_PORT="$port"
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

mongo_container_running() {
  [[ "$(docker inspect -f '{{.State.Running}}' "$MONGO_CONTAINER" 2>/dev/null)" == "true" ]]
}

ensure_mongo_container() {
  if mongo_container_running; then
    ok "MongoDB container '$MONGO_CONTAINER' is running."
    return 0
  fi
  if docker inspect "$MONGO_CONTAINER" >/dev/null 2>&1; then
    info "Starting existing MongoDB container '$MONGO_CONTAINER'..."
    docker start "$MONGO_CONTAINER" >/dev/null || return 1
  else
    info "Starting a standalone MongoDB 7 container (named volume $MONGO_VOLUME)..."
    docker run -d --name "$MONGO_CONTAINER" -p 27017:27017 \
      -v "$MONGO_VOLUME:/data/db" mongo:7 >/dev/null || return 1
  fi
  info "Waiting for MongoDB to accept connections..."
  local i
  for i in $(seq 1 15); do
    port_open 127.0.0.1 27017 && return 0
    sleep 2
  done
  return 1
}

# --- wizard steps -----------------------------------------------------------

choose_port() {
  local port owners
  while :; do
    port="$(prompt_value "Web port" "$DEFAULT_PORT")"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
      warn "Enter a numeric port between 1 and 65535."
      continue
    fi
    if port_open 127.0.0.1 "$port"; then
      owners="$(docker ps --format '{{.Names}}' --filter "publish=$port" 2>/dev/null || true)"
      if [[ "$owners" == *"webserver-web"* ]]; then
        ok "Port $port is used by the existing VulnBrief container; it will be recreated on this port."
        PORT="$port"
        return 0
      fi
      warn "Port $port is already in use (${owners:-unknown owner}). Pick another one."
      continue
    fi
    PORT="$port"
    return 0
  done
}

choose_mongo() {
  local choice uri
  echo
  info "MongoDB holds all VulnBrief data (databases 'web' and 'vulnerabilities')."
  printf '%s\n' "  1) MongoDB on this host (localhost:27017)  [default]"
  printf '%s\n' "  2) Custom MongoDB URI"
  choice="$(prompt_value "Choice" "1")"
  case "$choice" in
    2)
      while :; do
        uri="$(prompt_value "MongoDB URI (mongodb://[user:pass@]host:port/)" "")"
        [[ -n "$uri" ]] || { warn "URI cannot be empty."; continue; }
        break
      done
      if parse_mongo_target "$uri"; then
        if port_open "$MONGO_HOST" "$MONGO_PORT"; then
          ok "MongoDB reachable at ${MONGO_HOST}:${MONGO_PORT}."
        else
          warn "Cannot reach ${MONGO_HOST}:${MONGO_PORT} right now."
          confirm "Continue anyway? The app will not work until MongoDB is reachable." "n" || die "Aborted."
        fi
      else
        warn "Could not parse host/port from the URI; skipping the connectivity check."
      fi
      MONGO_URI="$uri"
      # Inside the container the same URI is used, overriding the compose default.
      MONGO_URI_DOCKER="$uri"
      ;;
    *)
      MONGO_URI="mongodb://localhost:27017/"
      MONGO_URI_DOCKER=""
      if port_open 127.0.0.1 27017; then
        ok "MongoDB reachable on localhost:27017."
      else
        warn "Nothing is listening on localhost:27017."
        if confirm "Start a standalone MongoDB container now?" "y"; then
          ensure_mongo_container || warn "MongoDB did not become ready in time."
        fi
        if port_open 127.0.0.1 27017; then
          ok "MongoDB is now reachable on localhost:27017."
        else
          warn "MongoDB is still not reachable on localhost:27017."
          confirm "Continue anyway? The app will not work until MongoDB is reachable." "n" || die "Aborted."
        fi
      fi
      ;;
  esac
}

choose_secret() {
  if confirm "Auto-generate a strong FLASK_SECRET_KEY?" "y"; then
    SECRET_KEY="$(generate_secret)"
  else
    SECRET_KEY="$(prompt_value "FLASK_SECRET_KEY" "")"
    [[ -n "$SECRET_KEY" ]] || die "FLASK_SECRET_KEY is required."
  fi
}

choose_bootstrap() {
  BOOTSTRAP_USER=""
  BOOTSTRAP_PASS=""
  echo
  info "On first start the app creates an initial admin user (default: admin / changeme)."
  confirm "Customize the initial admin account?" "n" || return 0
  BOOTSTRAP_USER="$(prompt_value "Admin username" "admin")"
  BOOTSTRAP_PASS="$(prompt_secret "Admin password (input hidden)" "changeme")"
  [[ "$BOOTSTRAP_PASS" == "changeme" ]] && warn "Keeping the default password is not recommended."
}

choose_tavily() {
  TAVILY_KEY=""
  echo
  info "Tavily is only needed for 'Enriched Weekly' reports (optional)."
  TAVILY_KEY="$(prompt_value "Tavily API key (Enter to skip)" "")"
}

choose_smtp() {
  SMTP_HOST="" SMTP_PORT="587" SMTP_USERNAME="" SMTP_PASSWORD=""
  SMTP_FROM="" SMTP_TLS="true" SMTP_SSL="false"
  echo
  confirm "Configure email delivery (SMTP) now?" "n" || return 0
  SMTP_HOST="$(prompt_value "SMTP host (empty to skip)" "")"
  [[ -n "$SMTP_HOST" ]] || { warn "SMTP left unconfigured."; SMTP_HOST=""; return 0; }
  SMTP_PORT="$(prompt_value "SMTP port" "587")"
  SMTP_USERNAME="$(prompt_value "SMTP username" "")"
  SMTP_PASSWORD="$(prompt_secret "SMTP password (input hidden)" "")"
  SMTP_FROM="$(prompt_value "From address" "")"
  if confirm "Use STARTTLS?" "y"; then SMTP_TLS="true"; else SMTP_TLS="false"; fi
  if confirm "Use SSL (implicit TLS)?" "n"; then SMTP_SSL="true"; else SMTP_SSL="false"; fi
}

write_env() {
  cp .env.example .env
  set_env_var .env WEB_PORT "$PORT"
  set_env_var .env LOCAL_MONGO_URI "$MONGO_URI"
  set_env_var .env LOCAL_MONGO_URI_DOCKER "$MONGO_URI_DOCKER"
  set_env_var .env FLASK_SECRET_KEY "$SECRET_KEY"
  set_env_var .env TAVILY_API_KEY "$TAVILY_KEY"
  set_env_var .env SMTP_HOST "$SMTP_HOST"
  set_env_var .env SMTP_PORT "$SMTP_PORT"
  set_env_var .env SMTP_USERNAME "$SMTP_USERNAME"
  set_env_var .env SMTP_PASSWORD "$SMTP_PASSWORD"
  set_env_var .env SMTP_FROM "$SMTP_FROM"
  set_env_var .env SMTP_USE_TLS "$SMTP_TLS"
  set_env_var .env SMTP_USE_SSL "$SMTP_SSL"
  [[ -n "$BOOTSTRAP_USER" ]] && set_env_var .env WEB_AUTH_BOOTSTRAP_USERNAME "$BOOTSTRAP_USER"
  [[ -n "$BOOTSTRAP_PASS" ]] && set_env_var .env WEB_AUTH_BOOTSTRAP_PASSWORD "$BOOTSTRAP_PASS"
  chmod 600 .env
  ok "Wrote .env (permissions 600)."
}

start_app() {
  info "Building and starting VulnBrief (first build can take a few minutes)..."
  "${COMPOSE[@]}" up -d --build || die "docker compose up failed."
  info "Waiting for the web app to answer on port $PORT..."
  if wait_for_web "$PORT"; then
    ok "VulnBrief is up."
  else
    warn "The app did not answer on port $PORT within 90 seconds. Last log lines:"
    "${COMPOSE[@]}" logs --tail=50 web || true
    die "Setup could not confirm the app is healthy. Check the logs above."
  fi
}

summary() {
  echo
  printf '%s\n' "${C_OK}${C_BOLD:-}Setup complete!${C_OFF}"
  printf '%s\n' "  Web UI:      http://localhost:$PORT"
  printf '%s\n' "  Login:       bootstrap admin account as configured during setup"
  printf '%s\n' "  Settings:    .env (secrets), config/config.json (tuning)"
  printf '%s\n' "  Change port: set WEB_PORT in .env, then: docker compose up -d"
  printf '%s\n' "  Stop:        docker compose down"
  printf '%s\n' "  Update:      ./update.sh"
  if [[ -z "$BOOTSTRAP_USER" && "${ran_wizard:-0}" -eq 1 ]]; then
    echo
    warn "The initial admin account uses the default credentials (admin / changeme)."
    warn "Change the password after your first login."
  fi
}

usage() {
  cat <<'EOF'
VulnBrief interactive setup (Docker)

Usage: ./setup.sh [-h|--help]

Walks through configuration (.env), makes sure MongoDB is reachable,
then builds and starts the app with Docker Compose.
EOF
}

# --- main -------------------------------------------------------------------

for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $arg (try --help)" ;;
  esac
done

command -v docker >/dev/null 2>&1 || die "Docker is required. Install it from https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || die "Docker daemon is not running. Start Docker and try again."
detect_compose || die "Docker Compose is required (docker compose plugin or docker-compose)."

ran_wizard=0
BOOTSTRAP_USER=""

echo
printf '%s\n' "${C_INFO}${C_BOLD:-}VulnBrief setup${C_OFF}"
printf '%s\n' "${C_DIM}This wizard configures .env, checks MongoDB, and starts the app with Docker.${C_OFF}"
echo

if [[ -f .env ]]; then
  info "Existing .env found."
  printf '%s\n' "  1) Keep it and (re)build/start the app  [default]"
  printf '%s\n' "  2) Re-run the configuration wizard (a backup of .env is kept)"
  printf '%s\n' "  3) Exit"
  choice="$(prompt_value "Choice" "1")"
  case "$choice" in
    2)
      backup=".env.bak.$(date +%Y%m%d-%H%M%S)"
      cp .env "$backup" && ok "Backed up .env to $backup"
      ran_wizard=1
      ;;
    3) exit 0 ;;
    *)
      PORT="$(env_value WEB_PORT "$DEFAULT_PORT")"
      [[ "$PORT" =~ ^[0-9]+$ ]] || PORT="$DEFAULT_PORT"
      ;;
  esac
else
  ran_wizard=1
fi

if [[ "$ran_wizard" -eq 1 ]]; then
  choose_port
  choose_mongo
  echo
  choose_secret
  choose_bootstrap
  choose_tavily
  choose_smtp
  write_env
else
  info "Keeping the existing .env."
fi

start_app
summary

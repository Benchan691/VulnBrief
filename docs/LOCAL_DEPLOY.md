# Local deployment (Python virtual environment)

This guide walks through running the web application on your machine using a
Python virtual environment. For Docker-based deployment, see [README.md](../README.md).

## What you will run

| Process | Command | Purpose |
|---------|---------|---------|
| Web UI | `app.py` or Gunicorn | Flask app on port **9100** |

All processes read the same **`.env`** file (loaded automatically on startup).
The web UI is usable for browsing newsletters and reviews with only MongoDB
configured. Enriched Weekly reports additionally need Tavily and llama-server.

## Prerequisites

Install on your machine:

- **Python 3.11+** (`python3 --version`)
- **Local MongoDB** with vulnerability source collections/review views (`vulnerabilities` DB) and application data (`web` DB)
- **Tavily API key** (for Enriched Weekly reports)
- **llama-server** OpenAI-compatible endpoint (for Enriched Weekly; see `enriched.llm_base_url` in `config/config.json`)

Optional:

- Self-signed TLS certs (`cert.pem`, `key.pem`) if you start the dev server with `python app.py`

## 1. Clone and enter the project

```sh
cd /path/to/webserver
```

## 2. Create and activate a virtual environment

```sh
python3 -m venv .venv
```

Activate it for your shell:

**macOS / Linux**

```sh
source .venv/bin/activate
```

**Windows (PowerShell)**

```powershell
.venv\Scripts\Activate.ps1
```

After activation, `python` and `pip` point inside `.venv`. The examples below
use `.venv/bin/python` so they work even if the venv is not activated.

## 3. Install dependencies

```sh
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

## 4. Start local MongoDB

The app uses a single local MongoDB server with two databases: `vulnerabilities`
for CVE/review data and `web` for users, sub accounts, and report jobs. Docker
Compose expects MongoDB on the **host** at port 27017 (`web` connects via
`host.docker.internal`).

**Option A — Standalone Docker container on the host port**

```sh
docker run -d \
  --name webserver-local-mongo \
  -p 27017:27017 \
  -v webserver-local-mongo-data:/data/db \
  mongo:7
```

**Option B — MongoDB installed on the host**

Use your system package manager or [MongoDB install docs](https://www.mongodb.com/docs/manual/installation/).
Default URI: `mongodb://localhost:27017/`

Verify connectivity:

```sh
mongosh "mongodb://localhost:27017/" --eval 'db.runCommand({ ping: 1 })'
```

Start Docker Compose only after local Mongo responds to the ping above.

## 5. Create configuration

**Non-sensitive settings:** [`config/config.json`](../config/config.json) (committed)

**Secrets and connection strings:** `.env` (gitignored)

```sh
cp .env.example .env
chmod 600 .env
```

Edit `.env` with the MongoDB URI and other credentials. Tune enriched, report, and
search limits in `config/config.json`. The app loads `.env` automatically when
any process starts (`app.py`) — you do not need to run
`source .env` manually.

Environment variables override `config/config.json` when both are set. Point at
a different JSON file with `APP_CONFIG=/path/to/config.json`.

### Minimum `.env` for local dev

| Variable | Purpose |
|----------|---------|
| `LOCAL_MONGO_URI` | Local MongoDB for both `web` and `vulnerabilities` databases (default `mongodb://localhost:27017/`) |
| `MONGO_URI` | Optional alias for `LOCAL_MONGO_URI` when both are set |
| `FLASK_SECRET_KEY` | Flask session signing (use a long random string) |
| `WEB_AUTH_BOOTSTRAP_USERNAME` | Exact username of the one local break-glass administrator |
| `WEB_AUTH_BOOTSTRAP_PASSWORD` | Local password for that administrator |
| `TAVILY_API_KEY` / `TAVILY_API_KEYS` | Tavily search (Enriched Weekly reports) |

### Account Hub sign-in (optional)

Set `ACCOUNT_HUB_ENABLED=true` and configure the full
`ACCOUNT_HUB_LOGIN_URL` (`/auth/user/oauth/login`) and
`ACCOUNT_HUB_TOKEN_CHECK_URL` (`/auth/open-api/v1/token/check`). Do not infer
URL paths in deployment code. The portal sends the submitted password Base64
encoded over HTTPS, as required by the API, then checks the returned tokens.
It admits the user only if `data.roles[].roleName` contains `CVE_SYSTEM`.
Bad credentials, inactive accounts, and missing roles block sign-in.

`/login/local` remains reserved for the local bootstrap administrator. A valid
Account Hub user is created locally on first login with role `user`. The
**Account Hub Users** page lets the local administrator set `user` or
`sub_admin`; Hub role changes do not overwrite that local choice. Local role
and disabled status are read on each request. Account Hub credentials and
tokens are checked at sign-in only; an existing portal session lasts up to 12
hours unless the local account is disabled or the user signs out.

After repeated failures, Account Hub may require `captchaVerification`. The
login form accepts that token, but the supplied API documentation does not
specify enough of the slider challenge protocol to embed a complete slider
widget. The token must be obtained from a compatible Account Hub CAPTCHA
client. Add an identity manually before creating a subscription for a user
who has not signed in yet; the subscription API still requires a local row.

If a development database contains records from the older schema, audit it
before enabling Account Hub:

```sh
.venv/bin/python scripts/cleanup_account_hub_migration.py \
  --bootstrap-username admin
```

The command is dry-run by default. It backs up candidates before deletion and
requires both `--apply --confirm` to remove incompatible documents and their
orphaned dependent records. It preserves the named bootstrap account and valid
Account Hub rows; vulnerability data and caches are not touched.

### Common `config/config.json` sections

| JSON path | Purpose |
|-----------|---------|
| `mongodb.*` | Database names |
| `report.*` | Report compaction settings |
| `enriched.*` | Enriched Weekly llama-server tuning |
| `tavily.*` | Search defaults |
| `account_hub.*` | Account Hub OAuth URLs, client settings, permission mappings, and timeout |

See [`.env.example`](../.env.example), [`config/config.json`](../config/config.json),
and [`core/config.py`](../core/config.py) for every supported setting.

## 6. TLS certificates (dev server only)

`python app.py` starts Flask with HTTPS using `cert.pem` and `key.pem` in the
project root. Generate a self-signed pair for local use:

```sh
openssl req -x509 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

Your browser will warn about the self-signed certificate; that is expected.

**Gunicorn** (recommended below) serves plain HTTP on port 9100 and does not
require these files.

## 7. Run the application

Open a terminal from the project root. Activate the venv (or use
the `.venv/bin/python` paths shown).

### Web server

**Development (Flask built-in server, HTTPS on 9100)**

```sh
.venv/bin/python app.py
```

Open: **https://localhost:9100**

**Production-style (Gunicorn, HTTP on 9100)**

```sh
.venv/bin/gunicorn -c gunicorn_config.py app:app
```

Open: **http://localhost:9100**

## 8. Sign in

When Account Hub is disabled, the bootstrap account is the local administrator;
local subscription users use username/password sign-in. Existing subscription
accounts without a configured password are migrated to the temporary password
`1234` and must change it after login.

When Account Hub is enabled, the bootstrap account remains available only as a
local break-glass administrator at `/login/local`. Normal users sign in through
Account Hub at `/login`, and administrators manage the approved-user allowlist
from **Account Hub Users**. Account Hub permission claims map to delegated
`sub_admin` or regular `user` roles using the configured permission strings.
Account Hub users do not have local passwords; revocation and disabled-row
checks are enforced on every protected request. The local bootstrap
administrator is the only full portal administrator.

For a separate local login while Account Hub is disabled, use:

```sh
.venv/bin/python scripts/create_auth_user.py myuser 'secure-password' --email you@example.com
```

The optional email is contact metadata only; it cannot be used to sign in. With
Account Hub enabled, this command instead approves an Account Hub username and
does not create a local password; omit the password argument in that mode:

```sh
.venv/bin/python scripts/create_auth_user.py hubuser --email you@example.com
```

## 9. Verify the setup

| Check | How |
|-------|-----|
| Web UI loads | Open http(s)://localhost:9100 and sign in |
| Local MongoDB | User appears under the `web` database `auth` collection |
| Tests | `.venv/bin/python -m pytest` |

## 10. Run tests

```sh
.venv/bin/python -m pytest
```

Tests set environment variables directly and do not require a live `.env` or
MongoDB.

## Minimal vs full setup

| Goal | Required services |
|------|-------------------|
| Browse newsletters / reviews | Web + local MongoDB (`vulnerabilities` DB) |
| Subscriptions and auth | Web + local MongoDB (`web` DB) |
| Fixed Template reports | Web + local MongoDB |
| Enriched Weekly reports | Web + local MongoDB + Tavily + llama-server |

## Troubleshooting

**`Missing required environment variable(s): LOCAL_MONGO_URI, FLASK_SECRET_KEY`**

Create `.env` from `.env.example` and set the required variables.

**`FileNotFoundError` for `cert.pem` when running `app.py`**

Generate TLS certs (step 6) or use Gunicorn instead.

**Cannot connect to MongoDB**

Confirm local Mongo is listening on port 27017. For Docker Compose, `web` uses
`host.docker.internal:27017`; data you inspect with `mongosh localhost:27017` is
the same server the UI uses (`web.sub_account`, `vulnerabilities.cve_review`, etc.).

**Subscription data not visible in MongoDB**

Sub accounts live in local MongoDB `web.sub_account`. Vulnerability data lives in
`vulnerabilities`. If the UI
shows subscribers but `mongosh` does not, you are likely connected to a different
Mongo instance than the app. With Docker Compose, use host Mongo on port 27017,
not a separate unpublished compose Mongo container.

**Enriched Weekly report fails**

Check `TAVILY_API_KEYS` in `.env` and `enriched.llm_base_url` in
`config/config.json`. The llama-server endpoint must accept OpenAI-compatible
`/v1/chat/completions` requests.

**Port 9100 already in use**

Stop the other process or change the bind address in `gunicorn_config.py` /
`app.py`.

## Stopping services

Press `Ctrl+C` in the terminal. To stop a standalone Docker MongoDB container:

```sh
docker stop webserver-local-mongo
```

## Security reminders

- Do not commit `.env`, `cert.pem`, or `key.pem`
- Use strong values for `FLASK_SECRET_KEY` and bootstrap passwords

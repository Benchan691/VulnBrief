# Local deployment (Python virtual environment)

This guide walks through running the web application on your machine using a
Python virtual environment. For Docker-based deployment, see [README.md](README.md).

## What you will run

| Process | Command | Purpose |
|---------|---------|---------|
| Web UI | `app.py` or Gunicorn | Flask app on port **6767** |
| Scheduler | `scheduler.py` | Scheduled report generation |

All processes read the same **`.env`** file (loaded automatically on startup).
The web UI is usable for browsing newsletters and reviews with only MongoDB
configured. Enriched Weekly reports additionally need Tavily or Exa and llama-server.

## Prerequisites

Install on your machine:

- **Python 3.11+** (`python3 --version`)
- **Atlas MongoDB** URI with vulnerability source collections and review views
- **Local MongoDB** for application data (auth, subscriptions, report jobs)
- **Tavily or Exa API key** (for Enriched Weekly reports)
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

The app stores users, subscriptions, report jobs, and schedules in a **local**
MongoDB instance (separate from Atlas). Docker Compose expects this database on
the **host** at port 27017 (`web` and `scheduler` connect via
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

**Non-sensitive settings:** [`config/config.json`](config/config.json) (committed)

**Secrets and connection strings:** `.env` (gitignored)

```sh
cp .env.example .env
chmod 600 .env
```

Edit `.env` with MongoDB URIs and other credentials. Tune enriched, report, and
search limits in `config/config.json`. The app loads `.env` automatically when
any process starts (`app.py`, `scheduler.py`) — you do not need to run
`source .env` manually.

Environment variables override `config/config.json` when both are set. Point at
a different JSON file with `APP_CONFIG=/path/to/config.json`.

### Minimum `.env` for local dev

| Variable | Purpose |
|----------|---------|
| `ATLAS_MONGO_URI` | Atlas connection for vulnerability data |
| `LOCAL_MONGO_URI` | Local MongoDB (default `mongodb://localhost:27017/`) |
| `FLASK_SECRET_KEY` | Flask session signing (use a long random string) |
| `TAVILY_API_KEY` / `TAVILY_API_KEYS` | Tavily search (Enriched Weekly reports) |
| `EXA_API_KEYS` | Exa search fallback (Enriched Weekly reports) |

### Common `config/config.json` sections

| JSON path | Purpose |
|-----------|---------|
| `mongodb.*` | Database names |
| `report.*` | Report compaction settings |
| `enriched.*` | Enriched Weekly llama-server tuning |
| `tavily.*` / `exa.*` | Search defaults |
| `scheduler.*` | Scheduler scan interval |

See [`.env.example`](.env.example), [`config/config.json`](config/config.json),
and [configuration.py](configuration.py) for every supported setting.

## 6. TLS certificates (dev server only)

`python app.py` starts Flask with HTTPS using `cert.pem` and `key.pem` in the
project root. Generate a self-signed pair for local use:

```sh
openssl req -x509 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

Your browser will warn about the self-signed certificate; that is expected.

**Gunicorn** (recommended below) serves plain HTTP on port 6767 and does not
require these files.

## 7. Run the application

Open separate terminals from the project root. Activate the venv in each (or use
the `.venv/bin/python` paths shown).

### Terminal 1 — web server

**Development (Flask built-in server, HTTPS on 6767)**

```sh
.venv/bin/python app.py
```

Open: **https://localhost:6767**

**Production-style (Gunicorn, HTTP on 6767)**

```sh
.venv/bin/gunicorn -c gunicorn_config.py app:app
```

Open: **http://localhost:6767**

### Terminal 2 — scheduler

```sh
.venv/bin/python scheduler.py
```

Handles cron-based scheduled report generation. Newsletter feeds query Atlas live from the web app and do not require the scheduler.

## 8. Sign in

On first startup, the app creates a bootstrap user from `WEB_AUTH_BOOTSTRAP_USERNAME`
and `WEB_AUTH_BOOTSTRAP_PASSWORD` in `.env` (default `admin` / `changeme`).
Change the password after first login, or create another user:

```sh
.venv/bin/python scripts/create_auth_user.py myuser 'secure-password' --email you@example.com
```

## 9. Verify the setup

| Check | How |
|-------|-----|
| Web UI loads | Open http(s)://localhost:6767 and sign in |
| Local MongoDB | User appears under the `web` database `auth` collection |
| Scheduler | Terminal 2 logs periodic scan cycles |
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
| Browse newsletters / reviews | Web + Atlas + local MongoDB |
| Subscriptions and auth | Web + local MongoDB |
| Fixed Template reports | Web + Atlas + local MongoDB |
| Enriched Weekly reports | Web + Atlas + local MongoDB + Tavily or Exa + llama-server |
| Scheduled reports | Web + scheduler + (report dependencies above) |

## Troubleshooting

**`Missing required environment variable(s): ATLAS_MONGO_URI, LOCAL_MONGO_URI, FLASK_SECRET_KEY`**

Create `.env` from `.env.example` and set the required variables.

**`FileNotFoundError` for `cert.pem` when running `app.py`**

Generate TLS certs (step 6) or use Gunicorn instead.

**Cannot connect to MongoDB**

Confirm local Mongo is listening on port 27017 and that Atlas allows your IP in
the cluster network access list. For Docker Compose, `web` and `scheduler` use
`host.docker.internal:27017`; data you inspect with `mongosh localhost:27017` is
the same database the UI uses (`web.subscriptions`, `report_jobs`, etc.).

**Subscription data not visible in MongoDB**

Subscriptions live in local MongoDB `web.subscriptions`, not Atlas. If the UI
shows subscribers but `mongosh` does not, you are likely connected to a different
Mongo instance than the app. With Docker Compose, use host Mongo on port 27017,
not a separate unpublished compose Mongo container.

**Enriched Weekly report fails**

Check `TAVILY_API_KEYS` or `EXA_API_KEYS` in `.env` and `enriched.llm_base_url` in
`config/config.json`. The llama-server endpoint must accept OpenAI-compatible
`/v1/chat/completions` requests.

**Port 6767 already in use**

Stop the other process or change the bind address in `gunicorn_config.py` /
`app.py`.

## Stopping services

Press `Ctrl+C` in each terminal. To stop a standalone Docker MongoDB container:

```sh
docker stop webserver-local-mongo
```

## Security reminders

- Do not commit `.env`, `cert.pem`, or `key.pem`
- Use strong values for `FLASK_SECRET_KEY` and bootstrap passwords

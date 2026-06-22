# Local deployment (Python virtual environment)

This guide walks through running the web application on your machine using a
Python virtual environment. For Docker-based deployment, see [README.md](README.md).

## What you will run

| Process | Command | Purpose |
|---------|---------|---------|
| Web UI | `app.py` or Gunicorn | Flask app on port **6767** |
| Preprocessor scanner | `company_ai_preprocessor.py --role scanner` | Optional/deprecated; disabled by default for normal report generation |
| Preprocessor router | `company_ai_preprocessor.py --role router` | Distributes on-demand report tasks to GPU or Company AI queues |
| Company AI worker | `company_ai_preprocessor.py --role company-worker` | Consumes Company AI queue tasks |
| Scheduler | `scheduler.py` | Scheduled report generation |

All processes read the same **`.env`** file (loaded automatically on startup).
The web UI is usable for browsing newsletters and reviews with only MongoDB
configured; AI reports need RabbitMQ and at least one enabled provider worker.

## Prerequisites

Install on your machine:

- **Python 3.11+** (`python3 --version`)
- **Atlas MongoDB** URI with vulnerability source collections and review views
- **Local MongoDB** for application data (auth, subscriptions, report jobs)
- **CloudAMQP** (or compatible RabbitMQ broker) for Company AI report mode
- **Company AI** credentials (only if you use the Company AI provider)

Optional:

- Self-signed TLS certs (`cert.pem`, `key.pem`) if you start the dev server with `python app.py`
- [GPU_server](GPU_server/README.md) on a separate host for local-model preprocessing

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

Edit `.env` with MongoDB URIs, RabbitMQ URL, Company AI secrets, and other
credentials. Tune queues, prompts, model names, and report limits in
`config/config.json`. The app loads `.env` automatically when any process starts
(`app.py`, `company_ai_preprocessor.py`, `scheduler.py`) — you do not need to
run `source .env` manually.

Environment variables override `config/config.json` when both are set. Point at
a different JSON file with `APP_CONFIG=/path/to/config.json`.

### Minimum `.env` for local dev

| Variable | Purpose |
|----------|---------|
| `ATLAS_MONGO_URI` | Atlas connection for vulnerability data |
| `LOCAL_MONGO_URI` | Local MongoDB (default `mongodb://localhost:27017/`) |
| `FLASK_SECRET_KEY` | Flask session signing (use a long random string) |
| `RABBITMQ_URL` | CloudAMQP URL (required for AI reports and preprocessor) |
| `COMPANY_AI_PASSWORD`, `COMPANY_AI_PUBLIC_KEY_B64`, `COMPANY_AI_SIGN_SECRET` | Company AI auth (when `company_ai.enabled` is true in JSON) |

Background preprocessing is disabled by default in `config/config.json`
(`flags.background_preprocessing_enabled`). Normal report generation enqueues
selected items into shared `ai_generation_tasks` at the configured report
priority; it does not write source `html_json`. Existing `html_json` fields are
legacy read-only cache data and do not require migration.

Long prompts and report messages can be edited directly in `config/config.json`
as normal JSON strings (including `\n` escapes).

### Common `config/config.json` sections

| JSON path | Purpose |
|-----------|---------|
| `mongodb.*` | Database and collection names |
| `rabbitmq.*` | Queue names and priorities |
| `company_ai.*` | Company AI URL, username, prompts, timeouts (no password) |
| `flags.*` | Feature toggles |
| `report.*` | Report compaction and JSON retry settings |
| `enriched.*` | Enriched Weekly Tavily/llama tuning |

When running the GPU worker stack (`GPU_server/`), align webserver
`config/config.json` with `GPU_server/config/gpu_server.json`:

| Webserver JSON | GPU JSON / default |
|----------------|-------------------|
| `rabbitmq.gpu_queue` | `rabbitmq.gpu_queue` |
| `gpu.worker_concurrency` | `inference.worker_concurrency` |
| `preprocessing.cache_version` | `processing.cache_version` |
| `report.max_depth` | `report_compaction.max_depth` |

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

### Terminal 1 — preprocessor router

```sh
.venv/bin/python company_ai_preprocessor.py --role router
```

Leave this running. It consumes `RABBITMQ_INTAKE_QUEUE` and distributes work to
`RABBITMQ_GPU_QUEUE` or `RABBITMQ_COMPANY_QUEUE`.

### Terminal 2 — Company AI worker

```sh
.venv/bin/python company_ai_preprocessor.py --role company-worker
```

Leave this running when `COMPANY_AI_ENABLED=true`. It consumes
`RABBITMQ_COMPANY_QUEUE` with `COMPANY_AI_PARALLEL_CHATS` workers. The scanner
role is optional/deprecated for normal operation; with the default
`BACKGROUND_PREPROCESSING_ENABLED=false`, it starts but does not scan source
collections or republish stale shared tasks. The legacy
`.venv/bin/python company_ai_preprocessor.py` command still starts scanner,
router, and Company AI worker together for local development.

### Terminal 3 — web server

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

### Terminal 4 — scheduler

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
| Preprocessor | Terminal 1 shows scan/worker activity without connection errors |
| Scheduler | Terminal 3 logs periodic scan cycles |
| Tests | `.venv/bin/python -m pytest` |

## 10. Run tests

```sh
.venv/bin/python -m pytest
```

Tests set environment variables directly and do not require a live `.env`,
MongoDB, or RabbitMQ.

## Minimal vs full setup

| Goal | Required services |
|------|-------------------|
| Browse newsletters / reviews | Web + Atlas + local MongoDB |
| Subscriptions and auth | Web + local MongoDB |
| Company AI reports | Web + preprocessor + RabbitMQ + Company AI |
| Scheduled reports | Web + scheduler + (report dependencies above) |
| GPU-backed AI tasks | Optional [GPU_server](GPU_server/README.md) + `GPU_ENABLED=true` |

To try the UI without AI, set `COMPANY_AI_ENABLED=false` in `.env` and use
**Fixed Template** report mode (see [AI_HARNESS.md](AI_HARNESS.md)).

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

**RabbitMQ / preprocessor errors**

Check `RABBITMQ_URL` and queue names match your CloudAMQP instance. Queues are
created on first use.

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
- Rotate broker and Company AI credentials if they are ever exposed

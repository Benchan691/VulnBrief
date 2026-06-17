# Local deployment (Python virtual environment)

This guide walks through running the web application on your machine using a
Python virtual environment. For Docker-based deployment, see [README.md](README.md).

## What you will run

| Process | Command | Purpose |
|---------|---------|---------|
| Web UI | `app.py` or Gunicorn | Flask app on port **6767** |
| Preprocessor scanner | `company_ai_preprocessor.py --role scanner` | Scans Atlas/shared tasks and publishes intake queue work |
| Preprocessor router | `company_ai_preprocessor.py --role router` | Distributes intake tasks to GPU or Company AI queues |
| Company AI worker | `company_ai_preprocessor.py --role company-worker` | Consumes Company AI queue tasks |
| Scheduler | `scheduler.py` | Scheduled report generation |

All processes read the same **`.env`** file (loaded automatically on startup).
The web UI is usable for browsing newsletters and reviews with only MongoDB
configured; AI reports and background preprocessing also need RabbitMQ and
Company AI credentials.

## Prerequisites

Install on your machine:

- **Python 3.11+** (`python3 --version`)
- **Atlas MongoDB** URI with vulnerability source collections and review views
- **Local MongoDB** for application data (auth, subscriptions, report jobs)
- **CloudAMQP** (or compatible RabbitMQ broker) for Company AI report mode and preprocessing
- **Company AI** credentials (only if you use AI reports or the preprocessor)

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

**All configuration lives in `.env`. Do not use `config/config.json`.**

`.env` is gitignored. Create it from the committed template:

```sh
cp .env.example .env
chmod 600 .env
```

Edit `.env` with your values. The app loads this file automatically when any
process starts (`app.py`, `company_ai_preprocessor.py`, `scheduler.py`) — you do
not need to run `source .env` manually.

### Minimum variables for local dev

| Variable | Purpose |
|----------|---------|
| `ATLAS_MONGO_URI` | Atlas connection for vulnerability data |
| `LOCAL_MONGO_URI` | Local MongoDB (default `mongodb://localhost:27017/`) |
| `FLASK_SECRET_KEY` | Flask session signing (use a long random string) |
| `RABBITMQ_URL` | CloudAMQP URL (required for AI reports and preprocessor) |
| `COMPANY_AI_*` | Company AI credentials (required when `COMPANY_AI_ENABLED=true`) |

`config/sources.json` is committed and lists vulnerability source collection
names used by the review UI. Its path is controlled by `SOURCES_CONFIG`
(default `config/sources.json`).

`config/preprocessing_priorities.json` controls background AI preprocessing
priority by collection and document field boosts. Override with
`PREPROCESSING_PRIORITIES_CONFIG`.

### Multiline values

Long prompts (`COMPANY_AI_START_PROMPT`, `COMPANY_AI_SUMMARY_PROMPT`,
`REPORT_JSON_ERROR_MESSAGE`) can use `\n` inside double-quoted strings in
`.env`. See [`.env.example`](.env.example) for the full variable list.

### Migrating from `config/config.json`

If you previously used `config/config.json`, copy values into `.env`:

| Old JSON path | Env variable |
|---------------|--------------|
| `atlas_mongo_uri` | `ATLAS_MONGO_URI` |
| `local_mongo_uri` | `LOCAL_MONGO_URI` |
| `local_database` / `web_database` | `LOCAL_DATABASE` |
| `vulnerabilities_database` | `VULNERABILITIES_DATABASE` |
| `flask_secret_key` | `FLASK_SECRET_KEY` |
| `review_view_suffix` | `REVIEW_VIEW_SUFFIX` |
| `rabbitmq.url` | `RABBITMQ_URL` |
| `rabbitmq.intake_queue` | `RABBITMQ_INTAKE_QUEUE` |
| `company_ai.base_url` | `COMPANY_AI_BASE_URL` |
| `company_ai.username` | `COMPANY_AI_USERNAME` |
| `company_ai.password` | `COMPANY_AI_PASSWORD` |
| `company_ai.enabled` | `COMPANY_AI_ENABLED` |
| `web_auth.bootstrap_username` | `WEB_AUTH_BOOTSTRAP_USERNAME` |
| `web_auth.bootstrap_password` | `WEB_AUTH_BOOTSTRAP_PASSWORD` |
| `gpu_preprocessing.enabled` | `GPU_ENABLED` |

When running the GPU worker stack (`GPU_server/`), align these webserver variables
with `GPU_server/config/gpu_server.json`:

| Webserver `.env` | GPU JSON / default |
|------------------|-------------------|
| `RABBITMQ_GPU_QUEUE=gpu_processing` | `rabbitmq.gpu_queue` |
| `GPU_WORKER_CONCURRENCY=1` | `inference.worker_concurrency` |
| `PREPROCESSING_CACHE_VERSION=1` | `processing.cache_version` |
| `REPORT_MAX_DEPTH=10` | `report_compaction.max_depth` |

See [`.env.example`](.env.example) and [configuration.py](configuration.py) for
every supported variable and its default.

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

### Terminal 1 — preprocessor scanner

```sh
.venv/bin/python company_ai_preprocessor.py --role scanner
```

Leave this running. It scans Atlas and shared report tasks, then publishes
pending work to `RABBITMQ_INTAKE_QUEUE`.

### Terminal 2 — preprocessor router

```sh
.venv/bin/python company_ai_preprocessor.py --role router
```

Leave this running. It consumes `RABBITMQ_INTAKE_QUEUE` and distributes work to
`RABBITMQ_GPU_QUEUE` or `RABBITMQ_COMPANY_QUEUE`.

### Terminal 3 — Company AI worker

```sh
.venv/bin/python company_ai_preprocessor.py --role company-worker
```

Leave this running when `COMPANY_AI_ENABLED=true`. It consumes
`RABBITMQ_COMPANY_QUEUE` with `COMPANY_AI_PARALLEL_CHATS` workers. The legacy
`.venv/bin/python company_ai_preprocessor.py` command still runs scanner,
router, and Company AI worker together for local development.

### Terminal 4 — web server

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

### Terminal 5 — scheduler

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

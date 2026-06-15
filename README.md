# web-AIprocess

Flask web application for managing cybersecurity newsletters, vulnerability review selections, subscriptions, and AI-assisted HTML report generation.

## Features

- **Newsletters** — browse filesystem newsletters plus source-specific newsletters rendered live from Atlas records
- **Subscriptions** — manage independent newsletter and report profiles with shared collection, severity/status, text, source, affected-system, and time filters
- **Vulnerability Reviews** — select records from MongoDB review collections for export and reporting
- **Reports** — generate structured reports with **Company AI** or a **Fixed Template**, then render preview/download HTML live without storing HTML in MongoDB.

Background workers pre-generate per-item AI JSON via routed RabbitMQ queues and
store results on vulnerability documents (`html_json.en`, `html_json.zh`,
`html_json.ch`). The optional standalone [`GPU_server`](GPU_server/README.md)
uses local GPUs for Atlas source tasks.

## Architecture

```mermaid
flowchart LR
  Browser --> Web["Flask web :6767"]
  Web --> Atlas["Atlas vulnerability MongoDB"]
  Web --> LocalMongo["Local application MongoDB"]
  Web --> CloudAMQP
  Scheduler["scheduler.py"] --> Atlas
  Scheduler --> LocalMongo
  Preprocessor["Company AI preprocessor + router"] --> CloudAMQP
  GPU["GPU_server worker"] --> CloudAMQP
  GPU --> Atlas
  Preprocessor --> Atlas
  Preprocessor --> LocalMongo
  Preprocessor --> CompanyAI["Company AI API"]
  Web --> CompanyAI
```

| Process | Role |
|---------|------|
| `web` | Flask UI, report job orchestration |
| `preprocessor` | Isolated RabbitMQ worker/router; scans Atlas and generates item/final summaries |
| `GPU_server` | Optional isolated local-model worker for source/shared AI tasks |
| `scheduler` | Claims cron schedules, generates scheduled reports, and synchronizes newsletter feed metadata |
| Atlas MongoDB | Vulnerability source data, review views, source AI cache, and shared AI tasks |
| Local MongoDB | Auth, subscriptions, newsletter metadata, structured report jobs/results, schedules, and locks |
| CloudAMQP | Priority-backed intake, GPU, and Company AI queues |

## Prerequisites

- Python 3.11+
- Atlas/web MongoDB containing vulnerability source collections and review views
- Local MongoDB for application-owned data
- [CloudAMQP](https://www.cloudamqp.com/) instance (or compatible AMQP broker)
- Company AI credentials (for AI report mode and preprocessor)

## Configuration

`config/config.json` is **not committed** (see `.gitignore`). Create it locally before running.

Minimum sections:

```json
{
  "atlas_mongo_uri": "mongodb+srv://user:password@atlas.example/",
  "local_mongo_uri": "mongodb://localhost:27017/",
  "local_database": "web",
  "vulnerabilities_database": "vulnerabilities",
  "flask_secret_key": "change-me",
  "newsletter_root": "newsletters",
  "rabbitmq": {
    "url": "amqps://user:password@host.lmq.cloudamqp.com/vhost",
    "intake_queue": "company_ai_preprocessing",
    "gpu_queue": "gpu_preprocessing",
    "company_queue": "company_ai_processing",
    "max_priority": 10,
    "background_priority": 1,
    "report_priority": 10
  },
  "company_ai": {
    "enabled": true,
    "auth_ttl_seconds": 3600,
    "login_max_failures": 3,
    "...": "..."
  },
  "company_ai_preprocessing": {
    "task_collection": "ai_generation_tasks",
    "...": "..."
  },
  "gpu_preprocessing": {
    "enabled": false,
    "final_summary_prompt": "Write the final summary in ${language}.",
    "...": "..."
  },
  "report_processing": { "...": "..." }
}
```

Environment variables can override **any** loaded setting (see `.env.example`). `config/config.json` is still required as the base file; env wins when both are set. List values accept JSON arrays (`["a","b"]`) or comma-separated strings (`a,b`).

TLS certificate files `cert.pem` and `key.pem` are also gitignored; keep them local if your deployment uses them.

## Quick start (Docker)

```sh
# 1. Create config/config.json (see above)
# 2. Export ATLAS_MONGO_URI. Docker Compose starts the local MongoDB service.

export ATLAS_MONGO_URI='mongodb+srv://...'
docker compose up -d --build
```

- Web UI: http://localhost:6767
- Services: `webserver-web`, `webserver-preprocessor`, `webserver-scheduler`, `webserver-local-mongo`

## Quick start (local Python)

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt

# Terminal 1 — preprocessor worker
.venv/bin/python company_ai_preprocessor.py

# Terminal 2 — web server
.venv/bin/python app.py

# Terminal 3 — report/newsletter scheduler
.venv/bin/python scheduler.py
```

Production-style local run uses Gunicorn on port **6767** (`gunicorn_config.py`).

## Tests

```sh
.venv/bin/python -m pytest
```

## Project layout

| Path | Description |
|------|-------------|
| `app.py` | Flask application entry |
| `company_ai_preprocessor.py` | RabbitMQ worker |
| `company_ai_auth_cache.py` | Process-wide Company AI token cache |
| `scheduler.py` | Scheduled report and newsletter synchronization worker |
| `newsletter_store.py` | Newsletter normalization, sanitization, live rendering, and feed metadata synchronization |
| `report_harness.py` | Report generation pipeline |
| `routes/` | HTTP blueprints (auth, newsletter, subscription, review, report) |
| `templates/` | Jinja HTML templates |
| `tests/` | Pytest suite |
| `AI_HARNESS.md` | Detailed report/preprocessor behavior and prompts |
| `GPU_server/` | Independent Ubuntu GPU preprocessing deployment |

## Security notes

- Do not commit `config/config.json`, `.env`, `cert.pem`, or `key.pem`
- Rotate CloudAMQP and Company AI credentials if they were ever exposed
- Use a strong `flask_secret_key` in production

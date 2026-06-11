# web-AIprocess

Flask web application for managing cybersecurity newsletters, vulnerability review selections, subscriptions, and AI-assisted HTML report generation.

## Features

- **Newsletters** — browse and publish newsletter HTML under `newsletters/`
- **Subscriptions** — manage subscriber records and run recent vulnerability selections (daily, weekly, or custom Asia/Hong_Kong window)
- **Vulnerability Reviews** — select records from MongoDB review collections for export and reporting
- **Reports** — generate HTML reports with **Company AI** (cached per-item JSON + live executive summary) or a **Fixed Template** (deterministic, English only)

Background workers pre-generate per-item Company AI JSON via RabbitMQ and store results on vulnerability documents (`html_json.en`, `html_json.zh`, `html_json.ch`).

## Architecture

```mermaid
flowchart LR
  Browser --> Web["Flask web :6767"]
  Web --> MongoDB
  Web --> CloudAMQP
  Preprocessor["company_ai_preprocessor.py"] --> CloudAMQP
  Preprocessor --> MongoDB
  Preprocessor --> CompanyAI["Company AI API"]
  Web --> CompanyAI
```

| Process | Role |
|---------|------|
| `web` | Flask UI, report job orchestration |
| `preprocessor` | RabbitMQ consumer; scans MongoDB and generates item summaries |
| MongoDB | Vulnerability data, `web.*` job/subscription collections |
| CloudAMQP | Queue `company_ai_preprocessing` (priority-backed) |

## Prerequisites

- Python 3.11+
- MongoDB (local or remote)
- [CloudAMQP](https://www.cloudamqp.com/) instance (or compatible AMQP broker)
- Company AI credentials (for AI report mode and preprocessor)

## Configuration

`config/config.json` is **not committed** (see `.gitignore`). Create it locally before running.

Minimum sections:

```json
{
  "mongo_uri": "mongodb://localhost:27017/",
  "web_database": "web",
  "vulnerabilities_database": "vulnerabilities",
  "flask_secret_key": "change-me",
  "newsletter_root": "newsletters",
  "rabbitmq": {
    "url": "amqps://user:password@host.lmq.cloudamqp.com/vhost",
    "queue_name": "company_ai_preprocessing",
    "max_priority": 10,
    "background_priority": 1,
    "report_priority": 10
  },
  "company_ai": { "...": "..." },
  "company_ai_preprocessing": { "...": "..." },
  "report_processing": { "...": "..." }
}
```

Environment variables can override **any** loaded setting (see `.env.example`). `config/config.json` is still required as the base file; env wins when both are set. List values accept JSON arrays (`["a","b"]`) or comma-separated strings (`a,b`).

TLS certificate files `cert.pem` and `key.pem` are also gitignored; keep them local if your deployment uses them.

## Quick start (Docker)

```sh
# 1. Create config/config.json (see above)
# 2. Ensure MongoDB is reachable from containers (Docker Desktop: host.docker.internal)

docker compose up -d --build
```

- Web UI: http://localhost:6767
- Services: `webserver-web`, `webserver-preprocessor`

## Quick start (local Python)

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt

# Terminal 1 — preprocessor worker
.venv/bin/python company_ai_preprocessor.py

# Terminal 2 — web server
.venv/bin/python app.py
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
| `report_harness.py` | Report generation pipeline |
| `routes/` | HTTP blueprints (auth, newsletter, subscription, review, report) |
| `templates/` | Jinja HTML templates |
| `tests/` | Pytest suite |
| `AI_HARNESS.md` | Detailed report/preprocessor behavior and prompts |

## Security notes

- Do not commit `config/config.json`, `.env`, `cert.pem`, or `key.pem`
- Rotate CloudAMQP and Company AI credentials if they were ever exposed
- Use a strong `flask_secret_key` in production

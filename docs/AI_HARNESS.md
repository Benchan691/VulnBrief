# Report Harness

The Reports page supports two generation modes:

- **Enriched Weekly** loads candidates only from MongoDB `cve` / `cve_review`,
  enriches those already-selected CVEs with Tavily search, extracts evidence and
  report sections through the configured llama-server OpenAI-compatible API, and
  validates the final 8-section report with Python plus an AI verification pass.
- **Fixed Template** copies source fields into a structured report and generates
  factual coverage and distribution summaries for severity/status, affected
  products or systems, remediation guidance, and references. Each template
  request runs independently in-process and does not call external AI providers.

Legacy UI values `ai` and `company_ai` map to `enriched_weekly`.

Enriched Weekly reports accept `report_language` values `en` (English), `zh`
(Traditional Chinese), and `ch` (Simplified Chinese). Fixed Template reports
remain English.

`enriched_weekly` jobs are CVE-only by design. Subscription profiles using this
mode force `filters.collections = ['cve_review']`, and manual report generation
rejects non-`cve_review` selections or uploaded JSON. Search APIs are used only after
MongoDB has produced a known CVE candidate; it must not discover or add new CVEs.

For each known CVE, enrichment builds focused Tavily sub-queries (advisory/patch,
optional vendor-domain filter via `include_domains`, NVD/CVSS, CISA/KEV, and
exploit/PoC). An optional job/profile `search_prompt` (max 200 characters) adds
one extra `{cve_id} {hint}` query per candidate; it never invents CVE IDs.
Default Tavily settings use `search_depth=advanced`, `max_results=8`, and
`chunks_per_source=3` (advanced search uses more Tavily credits than basic).

The pipeline stores run-scoped artifacts in the local `web` database under
`candidate_vulnerability_items`, `search_enrichment_tasks`,
`search_enrichment_results`, `filtered_enrichment_results`,
`source_evidence_cards`, `vulnerability_cards`, and `report_metrics`.

Database jobs fetch only the current review's `details` object; uploaded JSON
items must also contain a `details` object. Useless configured fields are removed
recursively and JSON is minified before it is sent to AI (`reports.template_builder.compact_details`).

Subscriptions are managed at `/subscriptions`. Each subscriber has independent
newsletter and report profiles using the same validated curated filters.
Newsletter profiles expose a local-MongoDB metadata feed with View and Copy HTML.
Those actions resolve the latest source record from the `vulnerabilities` database and render HTML live.
Report profile Run actions prepare the browser's Vulnerability Reviews selection
list for manual report generation on the Reports page.

## Enriched Weekly configuration

Secrets live in `.env` (`TAVILY_API_KEYS`). Other enriched/search settings live in
`config/config.json` under `enriched.*` and `tavily.*`. At least one Tavily key is required for search
enrichment. Tavily keys are used round-robin, one key per search request. `ENRICHED_LLM_BASE_URL` (or `enriched.llm_base_url` in JSON) must
point at a llama-server OpenAI-compatible `/v1` base URL. The pipeline calls that
endpoint directly for evidence extraction, report section generation, and AI
verification.

Common tunables:

| Setting | Purpose |
|---------|---------|
| `TAVILY_SEARCH_DEPTH` | Prefer `advanced` for richer enrichment snippets (costs more credits) |
| `TAVILY_MAX_RESULTS` | Results returned per Tavily query |
| `TAVILY_CHUNKS_PER_SOURCE` | Chunks per source when depth is `advanced` |
| `ENRICHED_LLM_MODEL` | Model name sent to llama-server |
| `ENRICHED_LLM_TIMEOUT_SECONDS` | Request timeout |
| `ENRICHED_LLM_MAX_OUTPUT_TOKENS` | Default max output tokens |
| `ENRICHED_LLM_EVIDENCE_MAX_OUTPUT_TOKENS` | Evidence extraction cap |
| `ENRICHED_LLM_REPORT_MAX_OUTPUT_TOKENS` | Report section cap |
| `ENRICHED_LLM_CONNECTION_RETRIES` | Connection retry count |
| `ENRICHED_LLM_PAGE_CHARS` | Max chars per fetched page |
| `ENRICHED_RESULTS_PER_TASK` | Ranked search results kept per CVE |
| `ENRICHED_EVIDENCE_CACHE_ENABLED` | Toggle evidence cache |
| `ENRICHED_EVIDENCE_CACHE_VERSION` | Cache invalidation version |

## Fixed Template configuration

Template reports use `report.*` in `config/config.json` for JSON compaction
when loading source `details` (`REPORT_DENY_KEYS`, `REPORT_MAX_DEPTH`, etc.).
No external AI calls are made.

## Report storage

Structured report data and job metadata are stored in the local MongoDB
`report_jobs` collection. Input references live temporarily in
`report_job_inputs`. Preview/download routes render HTML live and gradually
remove legacy stored HTML fields.

## Local startup

Create the virtual environment and install dependencies:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Start the web server:

```sh
.venv/bin/python app.py
```

Or start with Docker Compose (MongoDB must be reachable from containers,
for example via `host.docker.internal` on Docker Desktop):

```sh
docker compose up -d
```

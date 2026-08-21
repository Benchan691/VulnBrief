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
newsletter and report profiles. Both profiles can use a vendor/product CSV
inventory; newsletter and report inventories are stored separately. When a
newsletter inventory is enabled, only inventory-matched advisories are emailed.
Report profile Run actions prepare the browser's Vulnerability Reviews selection
list for manual report generation on the Reports page.

## Vendor/product CSV filters

The v1 CSV contract has exactly four columns, in this order:

```csv
vendor,product,vendor_aliases,product_aliases
```

| Column | Required | Meaning |
|---|---:|---|
| `vendor` | yes | Canonical manufacturer or publisher name. |
| `product` | yes | Canonical product, package, family, or model name. |
| `vendor_aliases` | no | Exact alternate vendor names, separated with `\|`. |
| `product_aliases` | no | Exact alternate product names, separated with `\|`. |

Each row is one vendor/product pair. Pairing is significant: do not put several
unrelated products into one cell. Use aliases only for real naming variants,
for example `RHEL|Red Hat Enterprise Linux`; broad terms such as `server` make
product-only evidence unreliable. Explicit aliases can also cover source
variants such as compatibility-width Unicode text.

- `vendor` and `product` are required on every non-blank row. Placeholder or
  punctuation-only identities such as `Unknown`, `N/A`, `*`, or `+++` are
  rejected.
- Files must be RFC 4180-compatible CSV encoded as UTF-8. A UTF-8 byte-order
  mark (BOM) is accepted. Quote cells that contain commas, double quotes, or
  line breaks according to normal CSV rules.
- A file may be at most 1 MiB with at most 500 data rows. Each cell may contain
  at most 200 characters, and each alias column may contain at most 10 aliases.
  Extremely complex inventories can require fewer rows or aliases to keep the
  database query safely below MongoDB's BSON command limit.
- Duplicate normalized vendor/product pairs are merged and reported as a
  warning. The import is atomic: any invalid row rejects the whole file.
- v1 deliberately does not accept or apply version filters. CVE version data is
  too incomplete and inconsistent to use as a safe exclusion rule.

A ready-to-edit example is available at
[`docs/vendor_product_filter_template.csv`](vendor_product_filter_template.csv).

New report profiles reject keyword filters. Existing stored keyword profiles are
kept read-only until an administrator loads a valid CSV and saves the
subscription (which replaces them atomically), or disables the report profile.
This compatibility rule prevents a routine edit from silently broadening an
active schedule to every product.

Matching preserves the vendor/product relationship within each CSV row and
assigns a confidence level:

- **Confirmed** means the vendor and product match the same structured affected
  product entry (CVE `details.affected` / CVE5 containers, AVD
  `affected_software`, GitHub Advisory package entries, CNNVD/Qianxin vendor
  and product fields, and similar structured source shapes).
- **Probable** means both names match bounded values in supported
  less-structured text fields (including source-specific lists such as
  HKCERT `systems_affected`, Cisco `product_names`, and Palo Alto `products`),
  and the source does not provide a complete conflicting affected-product pair.
- **Possible** means distinctive product evidence exists while structured
  vendor evidence is missing. It is opt-in, suppressed when the same product
  identity belongs to multiple imported vendors, and suppressed when the same
  text segment names another known inventory vendor. A vendor not present in
  the inventory cannot always be recognized from arbitrary prose, so possible
  matches must be reviewed as a recall-oriented queue rather than treated as
  confirmed attribution.

Confirmed and probable matches are included normally. Enabling **Include
possible matches** also includes possible matches, improving recall for
incomplete CVEs at the cost of more false positives. Leave it disabled when
precision is more important, and add aliases for known publisher naming
variants rather than using broad product terms.

A CVE with no usable vendor, product, alias, or other identity evidence cannot
be associated reliably with any inventory row. Such records remain unmatched
even when possible matches are included; otherwise every metadata-poor CVE
would become a false positive. The preview reports confidence counts so this
data-quality limitation is visible before the subscription is saved or run.

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

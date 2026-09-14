# Add severity filter to the email (newsletter) subscription section

## Finding
The report subscription form already has a severity filter (Critical/High/Medium/Low checkboxes + "Include unknown severity"). The backend **already validates and applies these exact fields (`status`, `include_unknown`) for the newsletter profile too** — `validate_filters` (subscriptions/profiles.py:240) accepts them, and the delivery path (`deliver_pending_newsletters` → `_newsletter_delivery_filter_overrides` in subscriptions/scheduler.py:764 → `build_severity_filter` in subscriptions/query.py:49) already honors them. The gap is purely frontend: `newsletterFilterMarkup()` never renders severity controls, and `readFilters('newsletter')` never sends them.

## Changes

### 1. `static/js/subscriptions/index.js` (only real change)
- **`newsletterFilterMarkup()`** (line 64): insert a severity block before the vendor/product import, mirroring `reportFilterMarkup()`:
  - Label `t('Severity / status')` + four checkboxes `newsletter-status-Critical|High|Medium|Low` with class `newsletter-status-checkbox`
  - Newsletter-specific help text: "Leave all unchecked to receive every new CVE, including ones without a severity yet." (differs from the report wording because newsletters currently include unknown-severity CVEs by default)
  - `newsletter-include-unknown` checkbox with existing label `t('Include unknown severity')`
- **`setStatusFilters()` / `readStatusFilters()`** (lines 410–427): replace the `report`-only special case (plus the dead legacy `prefix + '-status'` fallback that references a non-existent element) with one generic implementation reading/writing `#<prefix>-fields .<prefix>-status-checkbox` for both prefixes. Report markup keeps its existing class.
- **`setFilters()` newsletter branch** (line 430): before the early return, also restore severity checkboxes and the include-unknown checkbox from `filters.status` / `filters.include_unknown`.
- **`readFilters()` newsletter branch** (line 459): add `status: readStatusFilters('newsletter')` and `include_unknown: document.getElementById('newsletter-include-unknown').checked` to the saved payload.

### 2. `core/i18n.py`
- Add the one new help-text string with its Simplified Chinese translation in the `'ch'` dict (all other labels — 'Severity / status', severity names, 'Include unknown severity' — already exist and get reused).

## Behavior & compatibility (no backend change)
- Nothing checked → unchanged behavior: every new CVE delivered, including ones with no severity yet (enforced by `_newsletter_delivery_filter_overrides`, which only forces `include_unknown=True` when no severity filter is set).
- Severities checked → only those severities are emailed; unknown-severity CVEs only when "Include unknown severity" is checked.
- Existing subscriptions keep working as-is until edited (their stored filters have empty `status`).
- Time window and severity threshold are intentionally not added — the report section doesn't expose them either; this keeps the two sections consistent per your request.

## Verification
- Run `pytest tests/subscriptions/` to confirm nothing regressed.
- Manual check: open Subscriptions → Add/Edit, confirm the newsletter severity UI renders; save with severities selected; confirm the stored `newsletter_profile.filters.status`/`include_unknown` round-trips through GET `/api/subscriptions` and re-checks the boxes when re-opened.
from datetime import datetime, timezone

from reports.enriched.scorer import SEVERITY_WEIGHTS, normalize_severity, patch_priority
from reviews.normalizer import (
    extract_document_cve_id,
    extract_document_description,
    is_cve_record_document,
    normalize_cve_record_document,
    promote_cve_display_fields,
)

AUTO_SELECT_SCAN_LIMIT = 2000

_SEVERITY_RANK = {
    'Critical': 4,
    'High': 3,
    'Medium': 2,
    'Low': 1,
    'Unknown': 0,
}

_EXPLOIT_ACTIVE_TERMS = (
    'exploited',
    'in the wild',
    'active exploitation',
    'kev',
)
_POC_TERMS = (
    'proof of concept',
    'poc',
    'public exploit',
)
_IMPACT_TERMS = (
    'remote code',
    'ransomware',
    'internet-facing',
    'privilege',
)


def _prepare_document(document):
    if is_cve_record_document(document):
        return normalize_cve_record_document(document)
    return promote_cve_display_fields(document)


def _truthy(value):
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {'true', 'yes', '1'}
    return bool(value)


def _is_kev(document):
    details = document.get('details') if isinstance(document.get('details'), dict) else {}
    cve_details = details.get('cve') if isinstance(details.get('cve'), dict) else {}
    return any(_truthy(document.get(field)) for field in ('cisa_kev', 'kev')) or any(
        _truthy(cve_details.get(field)) for field in ('cisa_kev', 'kev')
    )


def _cna_base_score(document):
    cna = (document.get('containers') or {}).get('cna') or {}
    if not isinstance(cna, dict):
        return 0.0
    for metric in cna.get('metrics') or []:
        if not isinstance(metric, dict):
            continue
        for key in ('cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0'):
            data = metric.get(key)
            if not isinstance(data, dict):
                continue
            try:
                score = float(data.get('baseScore'))
            except (TypeError, ValueError):
                continue
            if score > 0:
                return score
    return 0.0


def _parse_datetime(value):
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    text = str(value).strip()
    if not text:
        return None
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _recency_bonus(disclosure_date, scraped_at, now=None):
    now = now or datetime.now(timezone.utc)
    candidates = [_parse_datetime(disclosure_date), _parse_datetime(scraped_at)]
    best_age_days = None
    for candidate in candidates:
        if candidate is None:
            continue
        age_days = max((now - candidate).total_seconds() / 86400, 0)
        if best_age_days is None or age_days < best_age_days:
            best_age_days = age_days
    if best_age_days is None:
        return 0
    if best_age_days <= 7:
        return 8
    if best_age_days <= 30:
        return 4
    return 0


def _cvss_bonus(cvss_score):
    if cvss_score >= 9.0:
        return 15
    if cvss_score >= 7.0:
        return 10
    if cvss_score >= 4.0:
        return 5
    return 0


def _exploit_and_impact_bonus(text):
    lowered = (text or '').lower()
    bonus = 0
    if any(term in lowered for term in _EXPLOIT_ACTIVE_TERMS):
        bonus += 12
    elif any(term in lowered for term in _POC_TERMS):
        bonus += 6
    if any(term in lowered for term in _IMPACT_TERMS):
        bonus += 8
    return bonus


def selection_score(document):
    doc = _prepare_document(document)
    severity = normalize_severity(
        doc.get('severity') or doc.get('status') or doc.get('impacts'),
    )
    score = SEVERITY_WEIGHTS.get(severity.lower(), 8)
    kev = _is_kev(doc)
    if kev:
        score += 25
    score += _cvss_bonus(_cna_base_score(doc))
    score += _exploit_and_impact_bonus(extract_document_description(doc))
    score += _recency_bonus(doc.get('disclosure_date'), doc.get('scraped_at'))
    return max(0, min(100, round(score, 1)))


def score_review_document(document):
    doc = _prepare_document(document)
    severity = normalize_severity(
        doc.get('severity') or doc.get('status') or doc.get('impacts'),
    )
    kev = _is_kev(doc)
    score = selection_score(doc)
    return {
        'selection_score': score,
        'patch_priority': patch_priority(score, severity, kev=kev),
        'cve_id': extract_document_cve_id(doc),
        'severity': severity,
        'disclosure_date': doc.get('disclosure_date'),
        'scraped_at': doc.get('scraped_at'),
    }


def _sort_datetime(value):
    parsed = _parse_datetime(value)
    return parsed or datetime.min.replace(tzinfo=timezone.utc)


def _selection_sort_key(row):
    return (
        row.get('selection_score', 0),
        _SEVERITY_RANK.get(row.get('severity') or 'Unknown', 0),
        _sort_datetime(row.get('disclosure_date')),
        _sort_datetime(row.get('scraped_at')),
        str(row.get('selection_id') or ''),
    )


def rank_scored_selections(scored_rows, count):
    if count <= 0:
        raise ValueError('count must be at least 1.')

    by_cve = {}
    for row in scored_rows:
        cve_id = (row.get('cve_id') or '').strip()
        if not cve_id:
            continue
        current = by_cve.get(cve_id)
        if current is None or _selection_sort_key(row) > _selection_sort_key(current):
            by_cve[cve_id] = row

    ranked = sorted(by_cve.values(), key=_selection_sort_key, reverse=True)
    return ranked[:count]

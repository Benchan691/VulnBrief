import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

from reviews.normalizer import (
    extract_document_cve_id,
    extract_document_description,
    extract_document_vendor_product,
    is_cve_record_document,
    normalize_cve_record_document,
)
from reviews.repository import MAX_EXPORT_SELECTIONS, resolve_vulnerability_document, review_views
from subscriptions.query import build_match_filter, severity_projection_fields

from .pipeline_collections import collection
from .reference_urls import filter_reference_urls


# Hosts that host CVE catalog/metadata, not vendor advisories.
_CATALOG_SOURCE_DOMAINS = frozenset({
    'github.com',
    'www.github.com',
    'raw.githubusercontent.com',
    'nvd.nist.gov',
    'cve.mitre.org',
    'cveawg.mitre.org',
    'cwe.mitre.org',
})


def _is_catalog_source_domain(host):
    normalized = (host or '').lower().strip('.')
    if not normalized:
        return False
    if normalized in _CATALOG_SOURCE_DOMAINS:
        return True
    return normalized.endswith('.githubusercontent.com')


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _text(value):
    if value is None:
        return ''
    if isinstance(value, list):
        return ' '.join(_text(item) for item in value)
    if isinstance(value, dict):
        return ' '.join(_text(item) for item in value.values())
    return str(value)


def _first_text(*values):
    for value in values:
        text = _text(value).strip()
        if text:
            return text
    return ''


def _nested_values(value, key_names):
    values = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in key_names:
                values.append(child)
            values.extend(_nested_values(child, key_names))
    elif isinstance(value, list):
        for item in value:
            values.extend(_nested_values(item, key_names))
    return values


def _first_nested_text(document, key_names):
    for value in _nested_values(document, set(key_names)):
        text = _text(value).strip()
        if text:
            return text
    return ''


def _source_url(document):
    source = document.get('source') if isinstance(document.get('source'), dict) else {}
    details = document.get('details') if isinstance(document.get('details'), dict) else {}
    return _first_text(
        source.get('url'),
        source.get('detail_url'),
        document.get('url'),
        document.get('source_url'),
        document.get('related_link'),
        _first_nested_text(details, ('url', 'source_url', 'detail_url', 'advisory_url')),
    )


def _references(document):
    values = [
        document.get('references'),
        document.get('reference_links'),
        document.get('related_links'),
    ]
    details = document.get('details') if isinstance(document.get('details'), dict) else {}
    values.extend(_nested_values(details, {'references', 'reference_links', 'related_links', 'url'}))
    refs = []
    for value in values:
        if isinstance(value, list):
            refs.extend(_text(item).strip() for item in value)
        else:
            text = _text(value).strip()
            if text:
                refs.append(text)
    seen = set()
    unique_refs = [ref for ref in refs if ref and not (ref in seen or seen.add(ref))]
    return filter_reference_urls(unique_refs, extract_document_cve_id(document))


def _content_hash(document):
    payload = {
        'title': document.get('title'),
        'summary': extract_document_description(document) or document.get('impacts'),
        'details': document.get('details'),
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def _detail_completeness_score(document):
    details = document.get('details') if isinstance(document.get('details'), dict) else {}
    score = 0
    if _text(details).strip():
        score += 1000
    for fields, points in (
        (('description', 'summary', 'overview', 'vulDesc'), 220),
        (('affected', 'affected_products', 'product', 'products'), 140),
        (('recommendation', 'recommendations', 'solution', 'mitigation'), 120),
        (('references', 'reference_links', 'related_links', 'url'), 90),
        (('severity', 'cvss_score'), 50),
        (('title', 'advisory_title'), 40),
    ):
        if _first_nested_text({'document': document, 'details': details}, fields):
            score += points
    score += min(len(_text(details)) // 80, 120)
    return score


def _vendor(document):
    vendor, _ = extract_document_vendor_product(document)
    return vendor


def _product(document):
    _, product = extract_document_vendor_product(document)
    return product


def _advisory_id(document, cve_id):
    return _first_text(document.get('advisory_id'), document.get('code'), cve_id)


def _vendor_domain(source_url, vendor, domain_map=None):
    domain_map = {str(key).lower(): value for key, value in (domain_map or {}).items()}
    if vendor and vendor.lower() in domain_map:
        return domain_map[vendor.lower()]
    host = urlparse(source_url or '').hostname or ''
    normalized = host.lower()
    if _is_catalog_source_domain(normalized):
        return ''
    return normalized


def normalize_candidate(document, run_id, position=0, domain_map=None):
    cve_id = extract_document_cve_id(document)
    if not cve_id:
        return None
    source_url = _source_url(document)
    vendor = _vendor(document)
    product = _product(document)
    content_hash = _content_hash(document)
    candidate_id = hashlib.sha256(f'{run_id}:{cve_id}:{content_hash}'.encode('utf-8')).hexdigest()[:24]
    summary = extract_document_description(document) or _first_text(document.get('impacts'))
    return {
        'run_id': run_id,
        'candidate_id': candidate_id,
        'position': position,
        'source_collection': 'cve',
        'selection_id': str(document.get('_id', '')),
        'cve_id': cve_id,
        'advisory_id': _advisory_id(document, cve_id),
        'vendor': vendor,
        'product': product,
        'title': _first_text(document.get('title'), cve_id),
        'severity': _first_text(document.get('severity')),
        'summary': summary,
        'published_at': document.get('published_at'),
        'observed_at': document.get('observed_at'),
        'source_url': source_url,
        'vendor_official_domain': _vendor_domain(source_url, vendor, domain_map),
        'references': _references(document),
        'content_hash': content_hash,
        'completeness_score': _detail_completeness_score(document),
        'raw_snapshot': document,
        'created_at': _now_iso(),
    }


def _dedupe_identity_keys(candidate):
    keys = {
        f"cve:{candidate['cve_id']}",
        f"advisory:{candidate.get('advisory_id') or ''}",
        f"title:{candidate.get('vendor') or ''}:{candidate.get('product') or ''}:{candidate.get('title') or ''}",
        f"hash:{candidate['content_hash']}",
    }
    source_url = str(candidate.get('source_url') or '').strip()
    cve_bare = candidate['cve_id'].removeprefix('CVE-').lower()
    if source_url and cve_bare in source_url.lower():
        keys.add(f"url:{source_url}")
    return {key for key in keys if not key.endswith(':') and not key.endswith('::')}


def dedupe_candidates(candidates):
    by_cve = {}
    for candidate in candidates:
        if not candidate:
            continue
        current = by_cve.get(candidate['cve_id'])
        if current is None or candidate['completeness_score'] > current['completeness_score']:
            by_cve[candidate['cve_id']] = candidate

    deduped = []
    seen_keys = set()
    for candidate in sorted(by_cve.values(), key=lambda item: item.get('position', 0)):
        keys = _dedupe_identity_keys(candidate)
        if seen_keys.intersection(keys):
            continue
        seen_keys.update(keys)
        deduped.append(candidate)
    return deduped


def _projection_pipeline(view):
    pipeline = list(view.get('options', {}).get('pipeline', []))
    if not pipeline or '$project' not in pipeline[0]:
        raise ValueError('Review view must begin with a projection.')
    first = dict(pipeline[0])
    projection = dict(first['$project'])
    projection.update({
        '_id': 1,
        **severity_projection_fields(),
        'observed_at': 1,
        'published_at': 1,
        'updated_at': 1,
        'details': 1,
        'source': 1,
        'cve_ids': 1,
    })
    first['$project'] = projection
    return [first, *pipeline[1:]]


def _cve_review_view(database):
    views = review_views(database)
    view = views.get('cve_review')
    if view and view.get('options', {}).get('viewOn') == 'cve':
        return view
    for candidate in views.values():
        if candidate.get('options', {}).get('viewOn') == 'cve':
            return candidate
    raise ValueError('cve_review view is required for enriched weekly reports.')


def query_cve_candidates(database, filters, limit=MAX_EXPORT_SELECTIONS, domain_map=None):
    view = _cve_review_view(database)
    mongo_filter = build_match_filter({**filters, 'collections': ['cve_review']})
    pipeline = _projection_pipeline(view)
    pipeline.extend([
        {'$match': mongo_filter},
        {'$sort': {'observed_at': 1, '_id': 1}},
    ])
    if limit is not None:
        pipeline.append({'$limit': limit + 1})
    candidates = [
        normalize_candidate(
            normalize_cve_record_document(document) if is_cve_record_document(document) else document,
            'query',
            position,
            domain_map,
        )
        for position, document in enumerate(database['cve'].aggregate(pipeline))
    ]
    deduped = dedupe_candidates(candidates)
    if limit is not None and len(deduped) > limit:
        raise ValueError(f'Filter result exceeds the {limit}-document limit.')
    return deduped


def load_candidates_from_inputs(run_id, vulnerability_database, web_database, inputs, domain_map=None):
    candidates = []
    for position, item in enumerate(inputs):
        if item.get('source_collection') != 'cve':
            raise ValueError('enriched_weekly reports only support cve_review selections.')
        document = resolve_vulnerability_document(
            vulnerability_database,
            'cve',
            item['selection_id'],
        )
        if document is None:
            raise ValueError(f"Selected CVE was not found: {item['selection_id']}")
        if is_cve_record_document(document):
            document = normalize_cve_record_document(document)
        candidate = normalize_candidate(document, run_id, position, domain_map)
        candidates.append(candidate)
    candidates = dedupe_candidates(candidates)
    target = collection(web_database, 'candidate_vulnerability_items')
    target.delete_many({'run_id': run_id})
    if candidates:
        target.insert_many(candidates)
    return candidates

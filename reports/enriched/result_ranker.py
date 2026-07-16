import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from .pipeline_collections import collection


SOURCE_PRIORITIES = {
    'vendor_advisory': 100,
    'package_notice': 90,
    'nvd_mitre': 80,
    'cisa': 75,
    'epss': 70,
    'release_notes': 65,
    'research_blog': 50,
    'news': 30,
    'other': 10,
}


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


def hostname(url):
    return (urlparse(url or '').hostname or '').lower()


def classify_source_type(url, title='', vendor_domain=''):
    host = hostname(url)
    haystack = f'{host} {title}'.lower()
    if vendor_domain and host.endswith(vendor_domain.lower()):
        return 'vendor_advisory'
    if 'nvd.nist.gov' in host or 'mitre.org' in host:
        return 'nvd_mitre'
    if 'cisa.gov' in host:
        return 'cisa'
    if 'first.org' in host or 'epss' in haystack:
        return 'epss'
    if any(term in haystack for term in ('github.com', 'npmjs.com', 'pypi.org', 'maven', 'nuget')):
        return 'package_notice'
    if any(term in haystack for term in ('release notes', 'changelog', 'security update')):
        return 'release_notes'
    if any(term in haystack for term in ('blog', 'research', 'labs', 'threat')):
        return 'research_blog'
    if any(term in haystack for term in ('news', 'bleepingcomputer', 'theregister')):
        return 'news'
    return 'other'


def _result_text(result):
    return ' '.join([
        _text(result.get('title')),
        _text(result.get('snippet')),
        _text(result.get('page_content')),
        _text(result.get('url')),
    ]).lower()


def is_relevant(result, candidate):
    text = _result_text(result)
    cve_id = candidate['cve_id'].lower()
    if cve_id in text:
        return True
    vendor = (candidate.get('vendor') or '').lower()
    product = (candidate.get('product') or '').lower()
    return bool(vendor and product and vendor in text and product in text)


def result_score(result, candidate):
    source_type = classify_source_type(
        result.get('url'),
        result.get('title') or '',
        candidate.get('vendor_official_domain') or '',
    )
    text = _result_text(result)
    score = SOURCE_PRIORITIES[source_type]
    if candidate['cve_id'].lower() in text:
        score += 25
    if (candidate.get('vendor') or '').lower() in text:
        score += 10
    if (candidate.get('product') or '').lower() in text:
        score += 10
    try:
        score += min(float(result.get('score') or 0) * 5, 5)
    except (TypeError, ValueError):
        pass
    return score, source_type


def _dedupe_key(result):
    normalized_url = re.sub(r'#.*$', '', (result.get('url') or '').rstrip('/'))
    return normalized_url.lower(), result.get('content_hash')


def rank_results_for_run(web_database, run_id, top_n=4):
    candidates = {
        item['candidate_id']: item
        for item in collection(web_database, 'candidate_vulnerability_items').find({'run_id': run_id})
    }
    raw_results = list(collection(web_database, 'search_enrichment_results').find({'run_id': run_id}))
    grouped = {}
    seen = set()
    for result in raw_results:
        candidate = candidates.get(result.get('candidate_id'))
        if candidate is None or not is_relevant(result, candidate):
            continue
        url_key, content_hash = _dedupe_key(result)
        scope = (result.get('candidate_id'), result.get('task_type'))
        url_seen_key = (*scope, 'url', url_key)
        hash_seen_key = (*scope, 'hash', content_hash)
        if url_seen_key in seen or (content_hash and hash_seen_key in seen):
            continue
        seen.add(url_seen_key)
        if content_hash:
            seen.add(hash_seen_key)
        score, source_type = result_score(result, candidate)
        ranked = dict(result)
        ranked['rank_score'] = score
        ranked['source_type'] = source_type
        ranked['ranked_at'] = _now_iso()
        grouped.setdefault((result['candidate_id'], result['task_type']), []).append(ranked)

    filtered = []
    for items in grouped.values():
        filtered.extend(sorted(items, key=lambda item: item['rank_score'], reverse=True)[:top_n])

    target = collection(web_database, 'filtered_enrichment_results')
    target.delete_many({'run_id': run_id})
    if filtered:
        target.insert_many(filtered)
    return filtered

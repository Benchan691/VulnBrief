from .cache_store import cache_key, mark_cache_hit, normalize_url, upsert_cache_payload
from .reference_urls import filter_reference_urls


def evidence_cache_key(cve_id, task_type, source_url, content_hash, cache_version='1'):
    return cache_key(
        str(cache_version),
        (cve_id or '').upper(),
        task_type or '',
        normalize_url(source_url),
        content_hash or '',
    )


def _payload_from_card(card):
    return {
        key: card.get(key)
        for key in (
            'confidence',
            'title',
            'what_happened',
            'why_matters',
            'how_to_respond',
            'affected_versions',
            'fixed_versions',
            'cvss_score',
            'cvss_vector',
            'exploit_status',
            'cisa_kev',
            'epss',
            'business_impact',
            'references',
        )
    }


def lookup_cached_payload(web_database, result, cache_version='1'):
    cache = web_database['source_evidence_cache']
    cache_key = evidence_cache_key(
        result.get('cve_id'),
        result.get('task_type'),
        result.get('url'),
        result.get('content_hash'),
        cache_version,
    )
    entry = cache.find_one({'cache_key': cache_key})
    if entry is None:
        return None
    mark_cache_hit(cache, cache_key)
    return dict(entry.get('payload') or {})


def delete_cached_payload(web_database, result, cache_version='1'):
    cache_key = evidence_cache_key(
        result.get('cve_id'),
        result.get('task_type'),
        result.get('url'),
        result.get('content_hash'),
        cache_version,
    )
    deleted = web_database['source_evidence_cache'].delete_one({'cache_key': cache_key})
    return int(deleted.deleted_count)


def purge_evidence_cache(web_database):
    result = web_database['source_evidence_cache'].delete_many({})
    return int(result.deleted_count)


def store_cached_payload(web_database, result, card, cache_version='1'):
    cache_key = evidence_cache_key(
        result.get('cve_id'),
        result.get('task_type'),
        result.get('url'),
        result.get('content_hash'),
        cache_version,
    )
    payload = _payload_from_card(card)
    payload['references'] = filter_reference_urls(
        payload.get('references') or [],
        result.get('cve_id'),
    )
    upsert_cache_payload(
        web_database['source_evidence_cache'],
        cache_key,
        {
            'cache_version': str(cache_version),
            'cve_id': result.get('cve_id'),
            'task_type': result.get('task_type'),
            'source_url': result.get('url') or '',
            'content_hash': result.get('content_hash') or '',
        },
        payload,
    )

from .cache_store import cache_key, mark_cache_hit, normalize_url, upsert_cache_payload


def search_results_cache_key(query_hash, url, content_hash, cache_version='1'):
    return cache_key(
        str(cache_version),
        query_hash or '',
        normalize_url(url),
        content_hash or '',
    )


def _payload_from_result(document):
    return {
        'url': document.get('url') or '',
        'title': document.get('title') or '',
        'snippet': document.get('snippet') or '',
        'page_content': document.get('page_content') or '',
        'score': document.get('score'),
        'source_api': document.get('source_api') or 'tavily',
        'content_hash': document.get('content_hash') or '',
    }


def lookup_cached_results(web_database, task, cache_version='1'):
    query_hash = task.get('query_hash')
    if not query_hash:
        return None
    cache = web_database['search_enrichment_cache']
    entries = list(cache.find({
        'query_hash': query_hash,
        'cache_version': str(cache_version),
    }))
    if not entries:
        return None
    for entry in entries:
        cache_key = entry.get('cache_key')
        if not cache_key:
            continue
        mark_cache_hit(cache, cache_key)
    return [dict(entry.get('payload') or {}) for entry in entries]


def store_cached_results(web_database, task, documents, cache_version='1'):
    query_hash = task.get('query_hash')
    if not query_hash or not documents:
        return
    cache = web_database['search_enrichment_cache']
    for document in documents:
        payload = _payload_from_result(document)
        if not payload['url']:
            continue
        cache_key = search_results_cache_key(
            query_hash,
            payload['url'],
            payload['content_hash'],
            cache_version,
        )
        upsert_cache_payload(
            cache,
            cache_key,
            {
                'cache_version': str(cache_version),
                'query_hash': query_hash,
                'query': task.get('query') or '',
            },
            payload,
        )


def purge_search_cache(web_database):
    result = web_database['search_enrichment_cache'].delete_many({})
    return int(result.deleted_count)

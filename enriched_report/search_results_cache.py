import hashlib
import re
from datetime import datetime, timezone

from .pipeline_collections import search_results_cache_collection


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _normalize_url(url):
    return re.sub(r'#.*$', '', (url or '').rstrip('/')).lower()


def search_results_cache_key(query_hash, url, content_hash, cache_version='1'):
    normalized = '|'.join([
        str(cache_version),
        query_hash or '',
        _normalize_url(url),
        content_hash or '',
    ])
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


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
    cache = search_results_cache_collection(web_database)
    entries = list(cache.find({
        'query_hash': query_hash,
        'cache_version': str(cache_version),
    }))
    if not entries:
        return None
    now = _now_iso()
    for entry in entries:
        cache_key = entry.get('cache_key')
        if not cache_key:
            continue
        cache.update_one(
            {'cache_key': cache_key},
            {'$set': {'last_used_at': now}, '$inc': {'hit_count': 1}},
        )
    return [dict(entry.get('payload') or {}) for entry in entries]


def store_cached_results(web_database, task, documents, cache_version='1'):
    query_hash = task.get('query_hash')
    if not query_hash or not documents:
        return
    cache = search_results_cache_collection(web_database)
    now = _now_iso()
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
        cache.update_one(
            {'cache_key': cache_key},
            {'$set': {
                'cache_key': cache_key,
                'cache_version': str(cache_version),
                'query_hash': query_hash,
                'query': task.get('query') or '',
                'payload': payload,
                'updated_at': now,
                'last_used_at': now,
            }, '$setOnInsert': {
                'created_at': now,
                'hit_count': 0,
            }},
            upsert=True,
        )

import hashlib
import re
from datetime import datetime, timezone

from .pipeline_collections import evidence_cache_collection


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _normalize_url(url):
    return re.sub(r'#.*$', '', (url or '').rstrip('/')).lower()


def evidence_cache_key(cve_id, task_type, source_url, content_hash, cache_version='1'):
    normalized = '|'.join([
        str(cache_version),
        (cve_id or '').upper(),
        task_type or '',
        _normalize_url(source_url),
        content_hash or '',
    ])
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


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
    cache_key = evidence_cache_key(
        result.get('cve_id'),
        result.get('task_type'),
        result.get('url'),
        result.get('content_hash'),
        cache_version,
    )
    entry = evidence_cache_collection(web_database).find_one({'cache_key': cache_key})
    if entry is None:
        return None
    evidence_cache_collection(web_database).update_one(
        {'cache_key': cache_key},
        {'$set': {'last_used_at': _now_iso()}, '$inc': {'hit_count': 1}},
    )
    return dict(entry.get('payload') or {})


def purge_evidence_cache(web_database):
    result = evidence_cache_collection(web_database).delete_many({})
    return int(result.deleted_count)


def store_cached_payload(web_database, result, card, cache_version='1'):
    cache_key = evidence_cache_key(
        result.get('cve_id'),
        result.get('task_type'),
        result.get('url'),
        result.get('content_hash'),
        cache_version,
    )
    now = _now_iso()
    evidence_cache_collection(web_database).update_one(
        {'cache_key': cache_key},
        {'$set': {
            'cache_key': cache_key,
            'cache_version': str(cache_version),
            'cve_id': result.get('cve_id'),
            'task_type': result.get('task_type'),
            'source_url': result.get('url') or '',
            'content_hash': result.get('content_hash') or '',
            'payload': _payload_from_card(card),
            'updated_at': now,
            'last_used_at': now,
        }, '$setOnInsert': {
            'created_at': now,
            'hit_count': 0,
        }},
        upsert=True,
    )

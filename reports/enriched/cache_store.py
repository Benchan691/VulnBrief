import hashlib
import re
from datetime import datetime, timezone


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_url(url):
    return re.sub(r'#.*$', '', (url or '').rstrip('/')).lower()


def cache_key(*parts):
    normalized = '|'.join(str(part or '') for part in parts)
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


def mark_cache_hit(collection, cache_key_value):
    collection.update_one(
        {'cache_key': cache_key_value},
        {'$set': {'last_used_at': now_iso()}, '$inc': {'hit_count': 1}},
    )


def upsert_cache_payload(collection, cache_key_value, fields, payload):
    now = now_iso()
    collection.update_one(
        {'cache_key': cache_key_value},
        {'$set': {
            'cache_key': cache_key_value,
            **fields,
            'payload': payload,
            'updated_at': now,
            'last_used_at': now,
        }, '$setOnInsert': {
            'created_at': now,
            'hit_count': 0,
        }},
        upsert=True,
    )

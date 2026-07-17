import hashlib
from datetime import datetime, timezone

from .pipeline_collections import collection
from .schemas import TASK_TYPES

ENRICHMENT_TASK_TYPE = TASK_TYPES[0]


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _query_hash(query):
    return hashlib.sha256(query.encode('utf-8')).hexdigest()


def _terms(candidate):
    cve_id = candidate['cve_id']
    vendor = candidate.get('vendor') or ''
    product = candidate.get('product') or ''
    domain = candidate.get('vendor_official_domain') or ''
    subject = ' '.join(part for part in (cve_id, vendor, product) if part).strip()
    return cve_id, vendor, product, domain, subject


def queries_for_candidate(candidate):
    cve_id, _vendor, _product, domain, subject = _terms(candidate)
    queries = [
        f'{subject} vulnerability advisory patch mitigation',
        f'site:{domain} {cve_id}' if domain else None,
        f'{cve_id} NVD CISA KEV exploit CVSS',
    ]
    return [query for query in queries if query]


def build_search_tasks(run_id, candidates):
    tasks = []
    now = _now_iso()
    for candidate in candidates:
        for query in queries_for_candidate(candidate):
            tasks.append({
                'run_id': run_id,
                'candidate_id': candidate['candidate_id'],
                'cve_id': candidate['cve_id'],
                'vendor': candidate.get('vendor') or '',
                'product': candidate.get('product') or '',
                'task_type': ENRICHMENT_TASK_TYPE,
                'query': query,
                'query_hash': _query_hash(query),
                'status': 'pending',
                'attempts': 0,
                'created_at': now,
                'updated_at': now,
            })
    return tasks


def write_search_tasks(web_database, run_id, candidates):
    tasks = build_search_tasks(run_id, candidates)
    target = collection(web_database, 'search_enrichment_tasks')
    target.delete_many({'run_id': run_id})
    if tasks:
        target.insert_many(tasks)
    return tasks

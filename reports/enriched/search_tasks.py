import hashlib
import re
from datetime import datetime, timezone

from .pipeline_collections import collection
from .schemas import TASK_TYPES

ENRICHMENT_TASK_TYPE = TASK_TYPES[0]
SEARCH_PROMPT_MAX_CHARS = 200


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _query_hash(query):
    return hashlib.sha256(query.encode('utf-8')).hexdigest()


def sanitize_search_prompt(value):
    if value is None:
        return ''
    if not isinstance(value, str):
        raise ValueError('Search prompt must be text.')
    cleaned = re.sub(r'[\x00-\x1f\x7f]', ' ', value)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    if len(cleaned) > SEARCH_PROMPT_MAX_CHARS:
        raise ValueError(f'Search prompt must be at most {SEARCH_PROMPT_MAX_CHARS} characters.')
    return cleaned


def _terms(candidate):
    cve_id = candidate['cve_id']
    vendor = (candidate.get('vendor') or '').strip()
    product = (candidate.get('product') or '').strip()
    domain = (candidate.get('vendor_official_domain') or '').strip()
    subject = ' '.join(part for part in (cve_id, vendor, product) if part).strip()
    return cve_id, vendor, product, domain, subject


def queries_for_candidate(candidate, search_prompt=''):
    """Return focused enrichment query specs for one known CVE candidate.

    Each item is ``{'query': str, 'include_domains': list[str]|None}``.
    Does not discover or invent CVE IDs.
    """
    cve_id, _vendor, _product, domain, subject = _terms(candidate)
    prompt = sanitize_search_prompt(search_prompt)
    specs = [
        {'query': f'{subject} security advisory patch fix', 'include_domains': None},
    ]
    if domain:
        specs.append({
            'query': f'{cve_id} advisory',
            'include_domains': [domain],
        })
    specs.extend([
        {'query': f'{cve_id} NVD CVSS', 'include_domains': None},
        {'query': f'{cve_id} CISA KEV', 'include_domains': None},
        {'query': f'{cve_id} exploit proof-of-concept', 'include_domains': None},
    ])
    if prompt:
        specs.append({
            'query': f'{cve_id} {prompt}',
            'include_domains': None,
        })

    unique = []
    seen = set()
    for spec in specs:
        query = (spec.get('query') or '').strip()
        if not query or query in seen:
            continue
        seen.add(query)
        domains = spec.get('include_domains') or None
        if domains:
            domains = [str(item).strip() for item in domains if str(item).strip()]
            domains = domains or None
        unique.append({'query': query, 'include_domains': domains})
    return unique


def build_search_tasks(run_id, candidates, search_prompt=''):
    prompt = sanitize_search_prompt(search_prompt)
    tasks = []
    now = _now_iso()
    for candidate in candidates:
        for spec in queries_for_candidate(candidate, prompt):
            task = {
                'run_id': run_id,
                'candidate_id': candidate['candidate_id'],
                'cve_id': candidate['cve_id'],
                'vendor': candidate.get('vendor') or '',
                'product': candidate.get('product') or '',
                'task_type': ENRICHMENT_TASK_TYPE,
                'query': spec['query'],
                'query_hash': _query_hash(spec['query']),
                'status': 'pending',
                'attempts': 0,
                'created_at': now,
                'updated_at': now,
            }
            if spec.get('include_domains'):
                task['include_domains'] = list(spec['include_domains'])
            tasks.append(task)
    return tasks


def write_search_tasks(web_database, run_id, candidates, search_prompt=''):
    tasks = build_search_tasks(run_id, candidates, search_prompt=search_prompt)
    target = collection(web_database, 'search_enrichment_tasks')
    target.delete_many({'run_id': run_id})
    if tasks:
        target.insert_many(tasks)
    return tasks

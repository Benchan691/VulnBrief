import hashlib
from datetime import datetime, timezone

from .pipeline_collections import collection
from .schemas import TASK_TYPES


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
    cve_id, vendor, product, domain, subject = _terms(candidate)
    vendor_site = f'site:{domain} {cve_id}' if domain else f'{subject} vendor advisory'
    return {
        'what_happened': [
            f'{subject} vulnerability advisory',
            f'{subject} what happened',
            f'{subject} root cause impact',
            vendor_site,
            f'{cve_id} NVD description',
            f'{cve_id} MITRE CVE record',
        ],
        'why_matters': [
            f'{subject} exploited in the wild',
            f'{subject} CISA KEV',
            f'{subject} EPSS exploit probability',
            f'{subject} CVSS score vector',
            f'{subject} ransomware threat intelligence',
            f'{subject} business impact',
        ],
        'how_to_respond': [
            f'{subject} fixed version patch',
            f'{subject} mitigation workaround',
            f'{subject} upgrade guidance',
            f'{subject} vendor security update',
            f'{subject} release notes',
            f'{subject} remediation steps',
        ],
    }


def build_search_tasks(run_id, candidates):
    tasks = []
    now = _now_iso()
    for candidate in candidates:
        queries_by_type = queries_for_candidate(candidate)
        for task_type in TASK_TYPES:
            for query in queries_by_type[task_type]:
                tasks.append({
                    'run_id': run_id,
                    'candidate_id': candidate['candidate_id'],
                    'cve_id': candidate['cve_id'],
                    'vendor': candidate.get('vendor') or '',
                    'product': candidate.get('product') or '',
                    'task_type': task_type,
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


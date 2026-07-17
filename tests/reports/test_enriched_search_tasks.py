from reports.enriched.search_tasks import build_search_tasks, queries_for_candidate
from reports.enriched.schemas import TASK_TYPES


def test_queries_for_candidate_without_vendor_domain_returns_two_queries():
    candidate = {
        'cve_id': 'CVE-2026-2000',
        'vendor': 'Acme',
        'product': 'Widget',
    }

    queries = queries_for_candidate(candidate)

    assert len(queries) == 2
    assert all('CVE-2026-2000' in query for query in queries)
    assert any('vulnerability advisory patch mitigation' in query for query in queries)
    assert any('NVD CISA KEV exploit CVSS' in query for query in queries)


def test_build_search_tasks_creates_enrichment_tasks_with_vendor_site_query():
    candidate = {
        'run_id': 'run',
        'candidate_id': 'candidate-1',
        'cve_id': 'CVE-2026-2000',
        'vendor': 'Acme',
        'product': 'Widget',
        'vendor_official_domain': 'acme.example',
    }

    tasks = build_search_tasks('run', [candidate])

    assert len(tasks) == 3
    assert {task['task_type'] for task in tasks} == set(TASK_TYPES)
    assert all(task['task_type'] == 'enrichment' for task in tasks)
    assert all('CVE-2026-2000' in task['query'] for task in tasks)
    assert any('site:acme.example' in task['query'] for task in tasks)

from reports.enriched.search_tasks import (
    build_search_tasks,
    queries_for_candidate,
    sanitize_search_prompt,
)
from reports.enriched.schemas import TASK_TYPES
import pytest


def test_queries_for_candidate_without_vendor_domain_returns_four_focused_queries():
    candidate = {
        'cve_id': 'CVE-2026-2000',
        'vendor': 'Acme',
        'product': 'Widget',
    }

    specs = queries_for_candidate(candidate)
    queries = [item['query'] for item in specs]

    assert len(specs) == 4
    assert all(item['include_domains'] is None for item in specs)
    assert all('CVE-2026-2000' in query for query in queries)
    assert any('security advisory patch fix' in query for query in queries)
    assert any(query == 'CVE-2026-2000 NVD CVSS' for query in queries)
    assert any(query == 'CVE-2026-2000 CISA KEV' for query in queries)
    assert any(query == 'CVE-2026-2000 exploit proof-of-concept' for query in queries)


def test_build_search_tasks_creates_enrichment_tasks_with_vendor_domain_filter():
    candidate = {
        'run_id': 'run',
        'candidate_id': 'candidate-1',
        'cve_id': 'CVE-2026-2000',
        'vendor': 'Acme',
        'product': 'Widget',
        'vendor_official_domain': 'acme.example',
    }

    tasks = build_search_tasks('run', [candidate])

    assert len(tasks) == 5
    assert {task['task_type'] for task in tasks} == set(TASK_TYPES)
    assert all(task['task_type'] == 'enrichment' for task in tasks)
    assert all('CVE-2026-2000' in task['query'] for task in tasks)
    vendor_tasks = [task for task in tasks if task.get('include_domains')]
    assert len(vendor_tasks) == 1
    assert vendor_tasks[0]['include_domains'] == ['acme.example']
    assert vendor_tasks[0]['query'] == 'CVE-2026-2000 advisory'


def test_build_search_tasks_appends_sanitized_search_prompt():
    candidate = {
        'candidate_id': 'candidate-1',
        'cve_id': 'CVE-2026-2000',
        'vendor': 'Acme',
        'product': 'Widget',
    }

    tasks = build_search_tasks('run', [candidate], search_prompt='  Exchange   RCE  ')

    assert any(task['query'] == 'CVE-2026-2000 Exchange RCE' for task in tasks)
    assert len(tasks) == 5


def test_sanitize_search_prompt_rejects_overlong_and_non_text():
    assert sanitize_search_prompt(None) == ''
    assert sanitize_search_prompt('  a\tb\n ') == 'a b'
    with pytest.raises(ValueError, match='at most 200'):
        sanitize_search_prompt('x' * 201)
    with pytest.raises(ValueError, match='must be text'):
        sanitize_search_prompt(123)

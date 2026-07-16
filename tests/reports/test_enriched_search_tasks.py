from reports.enriched.search_tasks import build_search_tasks
from reports.enriched.schemas import TASK_TYPES


def test_build_search_tasks_creates_three_task_groups_with_cve_queries():
    candidate = {
        'run_id': 'run',
        'candidate_id': 'candidate-1',
        'cve_id': 'CVE-2026-2000',
        'vendor': 'Acme',
        'product': 'Widget',
        'vendor_official_domain': 'acme.example',
    }

    tasks = build_search_tasks('run', [candidate])

    assert len(tasks) == len(TASK_TYPES) * 6
    assert {task['task_type'] for task in tasks} == set(TASK_TYPES)
    assert all('CVE-2026-2000' in task['query'] for task in tasks)
    assert any('site:acme.example' in task['query'] for task in tasks)


import json

from bson import ObjectId

from app import app
from reports.enriched.orchestrator import run_enriched_pipeline
from reports.enriched.pipeline_collections import purge_run_artifacts
from core.database import get_vulnerabilities_database, get_web_database
from reports.harness import create_job


class FakeTavilyClient:
    def search(self, query, *, include_domains=None):
        return [{
            'url': 'https://acme.example/advisory',
            'title': query,
            'content': 'CVE-2026-7000 affects Acme Widget and is fixed in 2.0.',
            'raw_content': (
                'CVE-2026-7000 affects Acme Widget. The issue allows remote code execution. '
                'Acme fixed the issue in version 2.0.'
            ),
        }]


class FailingTavilyClient:
    def search(self, query, *, include_domains=None):
        raise RuntimeError('401 Unauthorized')


class EmptyTavilyClient:
    def search(self, query, *, include_domains=None):
        return []


class FakeLlamaClient:
    evidence_max_output_tokens = 1024
    report_max_output_tokens = 4096

    def __init__(self):
        self.merge_sections = []

    def complete_text(self, system_prompt, user_prompt, **kwargs):
        payload = json.loads(user_prompt)
        if 'source' in payload:
            return json.dumps({
                'what_happened': 'Acme Widget has a remote code execution vulnerability.',
                'why_matters': 'Remote code execution can affect internet-facing systems.',
                'how_to_respond': 'Upgrade to version 2.0.',
                'confidence': 'medium',
            }), {}
        section_name = payload.get('section_name')
        if 'partial_sections' in payload:
            self.merge_sections.append(section_name)
            return json.dumps({
                'summary': 'Merged executive summary.',
                'key_findings': [
                    finding
                    for partial in payload['partial_sections']
                    for finding in partial.get('key_findings', [])
                ],
            }), {}
        if section_name == 'executive_summary':
            return json.dumps({
                'summary': 'One Acme Widget CVE requires patching.',
                'key_findings': ['Upgrade to 2.0.'],
            }), {}
        raise AssertionError(payload)


class IncompleteEvidenceLlamaClient:
    evidence_max_output_tokens = 1024
    report_max_output_tokens = 4096

    def complete_text(self, system_prompt, user_prompt, **kwargs):
        payload = json.loads(user_prompt)
        if 'source' in payload:
            return json.dumps({
                'required_output': {
                    'what_happened': 'The source confirms a vulnerability.',
                    'why_matters': None,
                    'how_to_respond': None,
                    'confidence': 'low',
                },
            }), {}
        raise AssertionError('Report generation must not run with incomplete evidence.')


def test_run_enriched_pipeline_completes_with_mocked_tavily_and_llm(monkeypatch):
    monkeypatch.setitem(app.config, 'TAVILY_API_KEY', 'fake')
    monkeypatch.setitem(app.config, 'ENRICHED_LLM_BASE_URL', 'http://llama.example/v1')
    monkeypatch.setitem(app.config, 'ENRICHED_RESULTS_PER_TASK', 1)
    with app.app_context():
        vulnerabilities = get_vulnerabilities_database()
        web = get_web_database()
        vulnerabilities['cve'].delete_many({'_id': 'cve:orchestrator'})
        vulnerabilities['cve'].insert_one({
            '_id': 'cve:orchestrator',
            'code': 'CVE-2026-7000',
            'title': 'Acme Widget RCE',
            'severity': 'Critical',
            'vendor': 'Acme',
            'product': 'Widget',
            'details': {'cve': {'description': 'Remote code execution.', 'affected_products': [{'vendor': 'Acme', 'product': 'Widget'}]}},
            'source': {'detail_url': 'https://acme.example/advisory'},
        })
        job_id = create_job([{
            'collection': 'cve_review',
            'source_collection': 'cve',
            'selection_id': 'cve:orchestrator',
        }], 'review_selections', 'enriched_weekly')
        try:
            run_enriched_pipeline(app, job_id, FakeTavilyClient(), FakeLlamaClient())

            job = web['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'completed'
            assert job['pipeline_stage'] == 'completed'
            assert job['progress_percent'] == 100
            assert job.get('status_message')
            assert any('enriched pipeline starting job=' in line for line in job['pipeline_logs'])
            assert job['report']['title'] == 'Weekly Cybersecurity Intelligence Report'
            row = job['report']['vulnerability_detail_table']['rows'][0]
            assert row['cve_id'] == 'CVE-2026-7000'
            assert row['what_happened'] == 'Acme Widget has a remote code execution vulnerability.'
            assert row['source_urls'] == ['https://acme.example/advisory']
            findings = job['report']['executive_summary']['key_findings']
            assert any('1 vulnerability reviewed.' in finding for finding in findings)
            assert any('Overall risk: Critical.' in finding for finding in findings)
            assert any('Acme Widget' in finding for finding in findings)
            assert 'vulnerability_navigation' not in job['report']
            assert 'appendix' not in job['report']
            assert 'weekly_risk_trend' not in job['report']
            assert 'remediation_playbook' not in job['report']
            assert 'research_scope' not in job['report']
            assert 'management_brief' not in job['report']
            assert web['candidate_vulnerability_items'].count_documents({'run_id': job_id}) == 1
        finally:
            purge_run_artifacts(web, job_id)
            web['report_jobs'].delete_many({'_id': ObjectId(job_id)})
            web['report_job_inputs'].delete_many({'job_id': ObjectId(job_id)})
            vulnerabilities['cve'].delete_many({'_id': 'cve:orchestrator'})


def test_run_enriched_pipeline_skips_removed_report_sections(monkeypatch):
    monkeypatch.setitem(app.config, 'TAVILY_API_KEY', 'fake')
    monkeypatch.setitem(app.config, 'ENRICHED_LLM_BASE_URL', 'http://llama.example/v1')
    monkeypatch.setitem(app.config, 'ENRICHED_RESULTS_PER_TASK', 1)
    monkeypatch.setitem(app.config, 'REPORT_SECTION_CHUNK_PROMPT_CHARS', 1)
    monkeypatch.setitem(app.config, 'REPORT_SECTION_CHUNK_CARD_COUNT', 2)
    cve_ids = [f'CVE-2026-70{index:02d}' for index in range(4)]
    with app.app_context():
        vulnerabilities = get_vulnerabilities_database()
        web = get_web_database()
        vulnerabilities['cve'].delete_many({'_id': {'$in': [f'cve:orchestrator-{index}' for index in range(4)]}})
        for index, cve_id in enumerate(cve_ids):
            vulnerabilities['cve'].insert_one({
                '_id': f'cve:orchestrator-{index}',
                'code': cve_id,
                'title': f'Acme Widget RCE {index}',
                'severity': 'Critical',
                'vendor': 'Acme',
                'product': 'Widget',
                'details': {'cve': {'description': 'Remote code execution.', 'affected_products': [{'vendor': 'Acme', 'product': 'Widget'}]}},
                'source': {'detail_url': f'https://acme.example/{cve_id}'},
            })
        job_id = create_job([
            {
                'collection': 'cve_review',
                'source_collection': 'cve',
                'selection_id': f'cve:orchestrator-{index}',
            }
            for index in range(4)
        ], 'review_selections', 'enriched_weekly')
        try:
            llama = FakeLlamaClient()
            run_enriched_pipeline(app, job_id, FakeTavilyClient(), llama)

            job = web['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'completed'
            assert len(job['report']['vulnerability_detail_table']['rows']) == 4
            assert 'vulnerability_navigation' not in job['report']
            assert 'appendix' not in job['report']
            assert 'weekly_risk_trend' not in job['report']
            assert 'remediation_playbook' not in job['report']
            assert 'remediation_playbook' not in llama.merge_sections
            assert 'weekly_risk_trend' not in llama.merge_sections
        finally:
            purge_run_artifacts(web, job_id)
            web['report_jobs'].delete_many({'_id': ObjectId(job_id)})
            web['report_job_inputs'].delete_many({'job_id': ObjectId(job_id)})
            vulnerabilities['cve'].delete_many({'_id': {'$in': [f'cve:orchestrator-{index}' for index in range(4)]}})


def test_run_enriched_pipeline_fails_when_all_tavily_tasks_fail(monkeypatch):
    monkeypatch.setitem(app.config, 'TAVILY_API_KEY', 'fake')
    monkeypatch.setitem(app.config, 'ENRICHED_LLM_BASE_URL', 'http://llama.example/v1')
    with app.app_context():
        vulnerabilities = get_vulnerabilities_database()
        web = get_web_database()
        vulnerabilities['cve'].delete_many({'_id': 'cve:all-searches-fail'})
        vulnerabilities['cve'].insert_one({
            '_id': 'cve:all-searches-fail',
            'code': 'CVE-2026-7999',
            'title': 'Acme Widget RCE',
            'severity': 'Critical',
            'vendor': 'Acme',
            'product': 'Widget',
            'details': {
                'cve': {
                    'description': 'Remote code execution.',
                    'affected_products': [{'vendor': 'Acme', 'product': 'Widget'}],
                },
            },
            'source': {'detail_url': 'https://acme.example/advisory'},
        })
        job_id = create_job([{
            'collection': 'cve_review',
            'source_collection': 'cve',
            'selection_id': 'cve:all-searches-fail',
        }], 'review_selections', 'enriched_weekly')
        try:
            run_enriched_pipeline(app, job_id, FailingTavilyClient(), FakeLlamaClient())

            job = web['report_jobs'].find_one({'_id': ObjectId(job_id)})
            task_count = web['search_enrichment_tasks'].count_documents({'run_id': job_id})
            assert job['status'] == 'failed'
            assert task_count >= 4
            assert f'All {task_count} Tavily search tasks failed' in job['error']
            assert '401 Unauthorized' in job['error']
            assert 'report' not in job
            assert web['search_enrichment_tasks'].count_documents({
                'run_id': job_id,
                'status': 'failed',
            }) == task_count
        finally:
            purge_run_artifacts(web, job_id)
            web['report_jobs'].delete_many({'_id': ObjectId(job_id)})
            web['report_job_inputs'].delete_many({'job_id': ObjectId(job_id)})
            vulnerabilities['cve'].delete_many({'_id': 'cve:all-searches-fail'})


def test_run_enriched_pipeline_fails_without_relevant_tavily_results(monkeypatch):
    monkeypatch.setitem(app.config, 'TAVILY_API_KEY', 'fake')
    monkeypatch.setitem(app.config, 'ENRICHED_LLM_BASE_URL', 'http://llama.example/v1')
    with app.app_context():
        vulnerabilities = get_vulnerabilities_database()
        web = get_web_database()
        vulnerabilities['cve'].delete_many({'_id': 'cve:no-search-evidence'})
        vulnerabilities['cve'].insert_one({
            '_id': 'cve:no-search-evidence',
            'code': 'CVE-2026-8000',
            'title': 'Acme Widget RCE',
            'severity': 'Critical',
            'vendor': 'Acme',
            'product': 'Widget',
            'details': {
                'cve': {
                    'description': 'Remote code execution.',
                    'affected_products': [{'vendor': 'Acme', 'product': 'Widget'}],
                },
            },
            'source': {'detail_url': 'https://acme.example/advisory'},
        })
        job_id = create_job([{
            'collection': 'cve_review',
            'source_collection': 'cve',
            'selection_id': 'cve:no-search-evidence',
        }], 'review_selections', 'enriched_weekly')
        try:
            run_enriched_pipeline(app, job_id, EmptyTavilyClient(), FakeLlamaClient())

            job = web['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'failed'
            assert 'No relevant Tavily search results were found for: CVE-2026-8000' in job['error']
            assert 'report' not in job
        finally:
            purge_run_artifacts(web, job_id)
            web['report_jobs'].delete_many({'_id': ObjectId(job_id)})
            web['report_job_inputs'].delete_many({'job_id': ObjectId(job_id)})
            vulnerabilities['cve'].delete_many({'_id': 'cve:no-search-evidence'})


def test_run_enriched_pipeline_fails_with_incomplete_evidence(monkeypatch):
    monkeypatch.setitem(app.config, 'TAVILY_API_KEY', 'fake')
    monkeypatch.setitem(app.config, 'ENRICHED_LLM_BASE_URL', 'http://llama.example/v1')
    with app.app_context():
        vulnerabilities = get_vulnerabilities_database()
        web = get_web_database()
        vulnerabilities['cve'].delete_many({'_id': 'cve:incomplete-evidence'})
        web['source_evidence_cache'].delete_many({'cve_id': 'CVE-2026-8001'})
        vulnerabilities['cve'].insert_one({
            '_id': 'cve:incomplete-evidence',
            'code': 'CVE-2026-8001',
            'title': 'Acme Widget RCE',
            'severity': 'Critical',
            'vendor': 'Acme',
            'product': 'Widget',
            'details': {
                'cve': {
                    'description': 'Remote code execution.',
                    'affected_products': [{'vendor': 'Acme', 'product': 'Widget'}],
                },
            },
            'source': {'detail_url': 'https://acme.example/advisory'},
        })
        job_id = create_job([{
            'collection': 'cve_review',
            'source_collection': 'cve',
            'selection_id': 'cve:incomplete-evidence',
        }], 'review_selections', 'enriched_weekly')
        try:
            run_enriched_pipeline(app, job_id, FakeTavilyClient(), IncompleteEvidenceLlamaClient())

            job = web['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'failed'
            assert 'Evidence extraction did not confirm required risk/impact' in job['error']
            assert 'CVE-2026-8001 (why_matters, how_to_respond)' in job['error']
            assert 'report' not in job
            assert web['source_evidence_cache'].count_documents({
                'cve_id': 'CVE-2026-8001',
            }) == 0
        finally:
            purge_run_artifacts(web, job_id)
            web['report_jobs'].delete_many({'_id': ObjectId(job_id)})
            web['report_job_inputs'].delete_many({'job_id': ObjectId(job_id)})
            web['source_evidence_cache'].delete_many({'cve_id': 'CVE-2026-8001'})
            vulnerabilities['cve'].delete_many({'_id': 'cve:incomplete-evidence'})

import json

from bson import ObjectId

from app import app
from enriched_report.orchestrator import run_enriched_pipeline
from enriched_report.pipeline_collections import purge_run_artifacts
from mongo import get_vulnerabilities_database, get_web_database
from report_harness import create_job


class FakeTavilyClient:
    def search(self, query):
        return [{
            'url': 'https://acme.example/advisory',
            'title': query,
            'content': 'CVE-2026-7000 affects Acme Widget and is fixed in 2.0.',
            'raw_content': (
                'CVE-2026-7000 affects Acme Widget. The issue allows remote code execution. '
                'Acme fixed the issue in version 2.0.'
            ),
        }]


class FakeLlamaClient:
    evidence_max_output_tokens = 1024
    report_max_output_tokens = 4096

    def complete_text(self, system_prompt, user_prompt, **kwargs):
        payload = json.loads(user_prompt)
        task_type = payload.get('task_type')
        if task_type == 'what_happened':
            return 'Acme Widget has a remote code execution vulnerability.', {}
        if task_type == 'why_matters':
            return 'Remote code execution can affect internet-facing systems.', {}
        if task_type == 'how_to_respond':
            return 'Upgrade to version 2.0.', {}
        section_name = payload.get('section_name')
        if section_name == 'remediation_playbook':
            cards = payload.get('vulnerability_cards') or []
            cve_ids = [card['cve_id'] for card in cards if card.get('cve_id')]
            return json.dumps({
                'summary': 'Chunk summary.',
                'actions': [{
                    'priority': 'High',
                    'action': f'Patch {cve_id}.',
                    'cve_ids': [cve_id],
                } for cve_id in cve_ids],
            }), {}
        if section_name == 'weekly_risk_trend':
            return json.dumps({
                'summary': 'Risk is concentrated in one critical CVE.',
                'trend_points': ['One critical Acme issue.'],
            }), {}
        if section_name == 'research_scope':
            return json.dumps({
                'summary': 'CVE-only Mongo discovery with Tavily enrichment.',
                'criteria': ['cve_review only'],
            }), {}
        if section_name == 'executive_summary':
            return json.dumps({
                'summary': 'One Acme Widget CVE requires patching.',
                'key_findings': ['Upgrade to 2.0.'],
            }), {}
        if section_name == 'management_brief':
            return json.dumps({
                'summary': 'Prioritize remediation for Acme Widget.',
                'business_impact': 'Potential service compromise.',
                'decisions_needed': ['Approve emergency patching.'],
            }), {}
        raise AssertionError(payload)


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
            'classification': {'best_vendor': 'Acme', 'best_product': 'Widget'},
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
            assert job['report']['title'] == 'Weekly Cybersecurity Intelligence Report'
            row = job['report']['vulnerability_detail_table']['rows'][0]
            assert row['cve_id'] == 'CVE-2026-7000'
            assert row['what_happened'] == 'Acme Widget has a remote code execution vulnerability.'
            assert row['source_urls'] == ['https://acme.example/advisory']
            assert job['report']['executive_summary']['summary'] == 'One Acme Widget CVE requires patching.'
            assert web['candidate_vulnerability_items'].count_documents({'run_id': job_id}) == 1
        finally:
            purge_run_artifacts(web, job_id)
            web['report_jobs'].delete_many({'_id': ObjectId(job_id)})
            web['report_job_inputs'].delete_many({'job_id': ObjectId(job_id)})
            vulnerabilities['cve'].delete_many({'_id': 'cve:orchestrator'})


def test_run_enriched_pipeline_chunks_remediation_playbook_for_large_reports(monkeypatch):
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
                'classification': {'best_vendor': 'Acme', 'best_product': 'Widget'},
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
            run_enriched_pipeline(app, job_id, FakeTavilyClient(), FakeLlamaClient())

            job = web['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'completed'
            actions = job['report']['remediation_playbook']['actions']
            assert len(actions) == 4
            assert {action['cve_ids'][0] for action in actions} == set(cve_ids)
        finally:
            purge_run_artifacts(web, job_id)
            web['report_jobs'].delete_many({'_id': ObjectId(job_id)})
            web['report_job_inputs'].delete_many({'job_id': ObjectId(job_id)})
            vulnerabilities['cve'].delete_many({'_id': {'$in': [f'cve:orchestrator-{index}' for index in range(4)]}})


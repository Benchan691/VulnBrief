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

    def complete_json(self, system_prompt, user_prompt, schema=None, schema_name='response', **kwargs):
        if schema_name == 'source_evidence_card':
            return {
                'run_id': 'ignored',
                'candidate_id': 'ignored',
                'cve_id': 'CVE-2026-7000',
                'task_type': 'what_happened',
                'source_url': 'https://acme.example/advisory',
                'confidence': 'high',
                'title': 'Acme advisory',
                'what_happened': 'Acme Widget has a remote code execution vulnerability.',
                'why_matters': 'Remote code execution can affect internet-facing systems.',
                'how_to_respond': 'Upgrade to version 2.0.',
                'affected_versions': ['before 2.0'],
                'fixed_versions': ['2.0'],
                'cvss_score': 9.8,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'exploit_status': 'not confirmed',
                'cisa_kev': False,
                'epss': 0.2,
                'business_impact': 'Potential service compromise.',
                'references': ['https://acme.example/advisory'],
                'extracted_at': '2026-06-18T00:00:00+00:00',
            }, {}
        if schema_name == 'enriched_vulnerability_detail_table':
            return {'rows': [{
                'cve_id': 'CVE-2026-7000',
                'title': 'Acme Widget RCE',
                'vendor': 'Acme',
                'product': 'Widget',
                'severity': 'Critical',
                'priority_score': 58,
                'patch_priority': 'Critical',
                'what_happened': 'Acme Widget has a remote code execution vulnerability.',
                'why_matters': 'Remote code execution can affect internet-facing systems.',
                'how_to_respond': 'Upgrade to version 2.0.',
                'source_urls': ['https://acme.example/advisory'],
            }]}, {}
        if schema_name == 'enriched_remediation_playbook':
            return {'summary': 'Patch Acme Widget first.', 'actions': [{
                'priority': 'High',
                'action': 'Upgrade Acme Widget to version 2.0.',
                'cve_ids': ['CVE-2026-7000'],
            }]}, {}
        if schema_name == 'enriched_appendix':
            return {'source_references': [{
                'cve_id': 'CVE-2026-7000',
                'url': 'https://acme.example/advisory',
                'source_type': 'vendor_advisory',
            }], 'metrics': {'total_vulnerabilities': 1}}, {}
        if schema_name == 'enriched_weekly_risk_trend':
            return {'summary': 'Risk is concentrated in one critical CVE.', 'trend_points': ['One critical Acme issue.']}, {}
        if schema_name == 'enriched_research_scope':
            return {'summary': 'CVE-only Mongo discovery with Tavily enrichment.', 'criteria': ['cve_review only']}, {}
        if schema_name == 'enriched_executive_summary':
            return {'summary': 'One Acme Widget CVE requires patching.', 'key_findings': ['Upgrade to 2.0.']}, {}
        if schema_name == 'enriched_management_brief':
            return {
                'summary': 'Prioritize remediation for Acme Widget.',
                'business_impact': 'Potential service compromise.',
                'decisions_needed': ['Approve emergency patching.'],
            }, {}
        if schema_name == 'enriched_report_verification':
            return {'unsupported_claims': []}, {}
        raise AssertionError(schema_name)


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
            assert job['report']['title'] == 'Enriched Weekly Cybersecurity Report'
            assert job['report']['vulnerability_detail_table']['rows'][0]['cve_id'] == 'CVE-2026-7000'
            assert web['candidate_vulnerability_items'].count_documents({'run_id': job_id}) == 1
        finally:
            purge_run_artifacts(web, job_id)
            web['report_jobs'].delete_many({'_id': ObjectId(job_id)})
            web['report_job_inputs'].delete_many({'job_id': ObjectId(job_id)})
            vulnerabilities['cve'].delete_many({'_id': 'cve:orchestrator'})

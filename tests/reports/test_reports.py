import json
import re
import threading
import time
from io import BytesIO

import pytest
from reports import harness as report_harness
from reports import jobs as report_jobs
from bson import ObjectId

from app import app
from core.database import get_vulnerabilities_database, get_web_database
from reports.harness import (
    _assemble_report,
    _finalize_item_result,
    _render_job_html,
    compact_details,
    compact_document,
    cancel_job,
    create_job,
    generate_template_report_data,
    run_report_translation,
    run_job,
    run_template_job,
)
from jsonschema import validate


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.app_context():
        get_web_database()['report_jobs'].delete_many({'input_source': 'test'})
        get_web_database()['report_job_inputs'].delete_many({})
        get_web_database()['report_job_results'].delete_many({})
        get_web_database()['report_worker_locks'].delete_many({})
    client = app.test_client()
    yield client
    with app.app_context():
        get_web_database()['report_jobs'].delete_many({'input_source': 'test'})
        get_web_database()['report_job_inputs'].delete_many({})
        get_web_database()['report_job_results'].delete_many({})
        get_web_database()['report_worker_locks'].delete_many({})


def authenticate(client):
    with client.session_transaction() as session:
        session['username'] = 'test-user'


def sample_document(index=1):
    return {
        '_id': f'test:{index}',
        'schema_version': 2,
        'code': str(index),
        'title': f'Vulnerability {index}',
        'severity': 'High',
        'details': {
            'description': 'Evidence-based description.',
            'affected_products': ['Product A'],
            'reference_links': ['https://example.com'],
            'raw': {'large': 'must be removed'},
        },
        'source': {'detail_url': 'https://example.com/source'},
    }


class EchoTranslationClient:
    report_max_output_tokens = 2048

    def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
        payload = user_prompt[user_prompt.rfind('\n\n') + 2:]
        return payload.replace('Cybersecurity', '網絡安全').replace('Live report', '即時報告'), {}


def test_compaction_removes_raw_payload():
    compacted = compact_document(sample_document())
    assert 'raw' not in json.dumps(compacted)
    assert compacted['details']['description'] == 'Evidence-based description.'


def test_compaction_preserves_top_level_template_fields():
    compacted = compact_document({
        '_id': 'top-level',
        'cve': 'CVE-TOP',
        'severity': 'CRITICAL',
        'summary': 'Top-level summary.',
        'affected': ['Product A'],
        'recommendation': 'Apply patch.',
        'references': ['https://example.com/top'],
    })

    assert compacted['code'] == 'CVE-TOP'
    assert compacted['severity'] == 'CRITICAL'
    assert compacted['summary'] == 'Top-level summary.'
    assert compacted['recommendations'] == 'Apply patch.'


def test_details_compaction_removes_useless_fields_and_newlines():
    compacted = compact_details({
        'source': {
            'description': 'line one\n line two',
            'raw_fields': {'large': True},
            'raw_extra': 'remove',
            'empty': '',
            'products': ['A', 'A', None],
        },
    }, {
        'REPORT_DENY_KEYS': ['raw_fields'],
        'REPORT_DENY_PREFIXES': ['raw_'],
        'REPORT_MAX_DEPTH': 6,
        'REPORT_MAX_LIST_ITEMS': 100,
        'REPORT_MAX_STRING_CHARS': 12000,
    })

    assert compacted == {
        'source': {'description': 'line one line two', 'products': ['A']},
    }


def test_template_generation_maps_source_fields_and_counts():
    report = generate_template_report_data([
        {
            'code': 'CVE-TEST-1',
            'title': 'First vulnerability',
            'severity': 'High',
            'source': {'detail_url': 'https://example.com/source-detail'},
            'details': {
                'summary': 'Source summary.',
                'affected_products': ['Product A', 'product a'],
                'references': {'advisory': 'https://example.com/advisory'},
                'solution': ['Apply update.', 'apply update.'],
            },
        },
        {
            'code': 'CVE-TEST-2',
            'severity': 'Medium',
            'details': {
                'description': 'Second source description.',
                'systems_affected': 'Product B',
                'recommendation': 'Restrict access.',
            },
        },
    ])

    assert report['title'] == 'Cybersecurity Report'
    validate(instance=report, schema=report_harness.REPORT_SCHEMA)
    assert report['template_mode'] is True
    assert report['executive_summary'] == ''
    assert report['trends'] == []
    assert report['recommendations'] == []
    assert report['highlights'][0]['title'] == 'First vulnerability'
    assert report['highlights'][0]['code'] == 'CVE-TEST-1'
    assert report['highlights'][0]['severity'] == 'High'
    assert report['highlights'][0]['source_link'] == 'https://example.com/source-detail'
    assert report['highlights'][0]['newsletter']['overview'] == 'Source summary.'
    assert report['highlights'][0]['newsletter']['affected'] == ['Product A']
    assert report['highlights'][0]['newsletter']['recommendations'] == ['Apply update.']
    assert report['highlights'][0]['newsletter']['references'] == [
        'https://example.com/source-detail',
        'https://example.com/advisory',
    ]
    assert report['highlights'][1]['title'] == 'CVE-TEST-2'


def test_template_generation_maps_cnnvd_fields():
    report = generate_template_report_data([{
        'title': 'Spring Security 资源管理错误漏洞',
        'source_collection': 'cnnvd',
        'details': {
            'vulName': 'Spring Security 资源管理错误漏洞',
            'cveCode': 'CVE-2026-40988',
            'hazardLevel': 'High',
            'vulDesc': 'Spring Security存在资源管理错误漏洞。',
            'affectedVendor': 'Spring',
            'patch': 'https://spring.io/security/cve-2026-40988',
            'referUrl': '链接:https://nvd.nist.gov/vuln/detail/CVE-2026-40988',
        },
    }])

    highlight = report['highlights'][0]
    assert highlight['title'] == 'Spring Security 资源管理错误漏洞'
    assert highlight['code'] == 'CVE-2026-40988'
    assert highlight['severity'] == 'High'
    assert highlight['summary'] == 'Spring Security存在资源管理错误漏洞。'
    assert highlight['newsletter']['affected'] == ['Spring']
    assert highlight['newsletter']['recommendations'] == ['https://spring.io/security/cve-2026-40988']
    assert highlight['newsletter'].get('references') is None


def test_template_generation_strips_html_from_source_fields():
    html_description = (
        '<p>A vulnerability in the CLI of Cisco Catalyst SD-WAN Manager could allow '
        'an attacker to execute arbitrary commands as <em>root</em>.</p>'
        '<p>This vulnerability is due to insufficient validation of user-supplied input.'
        '&nbsp;</p>'
        '<p>See <a href="https://example.com/advisory">CVE-2026-20182</a> for details.</p>'
    )
    report = generate_template_report_data([{
        'title': '<strong>Cisco Advisory</strong>',
        'details': {'description': html_description},
    }])

    summary = report['highlights'][0]['summary']
    assert '<p>' not in summary
    assert '<em>' not in summary
    assert 'root' in summary
    assert 'CVE-2026-20182' in summary
    assert '<p>' in report['highlights'][0]['newsletter']['overview']
    assert report['highlights'][0]['title'] == 'Cisco Advisory'


def test_create_job_requires_at_least_one_record():
    with pytest.raises(ValueError, match='At least one vulnerability record is required'):
        create_job([], 'test')


def test_template_generation_uses_missing_field_fallbacks():
    report = generate_template_report_data([{'details': {}}])

    assert report['highlights'][0]['title'] == 'Vulnerability record 1'
    assert report['highlights'][0]['summary'] == (
        'No overview was provided in the source record.'
    )
    assert report['recommendations'] == []
    assert report['trends'] == []


def test_reports_api_upload_and_authentication(client, monkeypatch):
    assert client.get('/reports').status_code == 302
    authenticate(client)
    page = client.get('/reports')
    assert page.status_code == 200
    assert b'/static/js/reports/index.js' in page.data
    match = re.search(
        rb'<script id="page-config" type="application/json">(.*?)</script>',
        page.data,
        re.DOTALL,
    )
    assert match
    assert json.loads(match.group(1))['jobsUrl'] == '/api/reports'
    monkeypatch.setattr('reports.routes.start_job', lambda app, job_id: None)
    response = client.post('/api/reports', data={
        'json_file': (BytesIO(b'[]'), 'input.json'),
    })
    assert response.status_code == 400

    response = client.post('/api/reports', data={
        'json_file': (BytesIO(json.dumps([sample_document()]).encode()), 'input.json'),
    })
    assert response.status_code == 202
    assert response.get_json()['status'] == 'running'
    job_id = ObjectId(response.get_json()['id'])
    with app.app_context():
        job = get_web_database()['report_jobs'].find_one({'_id': job_id})
        assert job['status'] == 'running'
        assert job['generation_mode'] == 'template'
        assert job['effective_generation_mode'] == 'template'
        assert job['report_language'] == 'en'
        assert job['effective_report_language'] == 'en'
        assert get_web_database()['report_job_inputs'].count_documents({'job_id': job_id}) == 1
        get_web_database()['report_jobs'].delete_one({'_id': job_id})
        get_web_database()['report_job_inputs'].delete_many({'job_id': job_id})

    response = client.post('/api/reports', data={
        'generation_mode': 'invalid',
        'json_file': (BytesIO(json.dumps([sample_document()]).encode()), 'input.json'),
    })
    assert response.status_code == 400
    assert response.get_json()['error'] == (
        'Generation mode must be "template" or "enriched_weekly".'
    )

    response = client.post('/api/reports', data={
        'generation_mode': 'ai',
        'json_file': (BytesIO(json.dumps([sample_document()]).encode()), 'input.json'),
    })
    assert response.status_code == 400
    assert 'enriched_weekly reports require cve_review selections' in response.get_json()['error']

    response = client.post('/api/reports', data={
        'generation_mode': 'enriched_weekly',
        'report_language': 'invalid',
        'json_file': (BytesIO(json.dumps([sample_document()]).encode()), 'input.json'),
    })
    assert response.status_code == 400
    assert response.get_json()['error'] == 'Report language must be "en", "zh", or "ch".'

    response = client.post('/api/reports', data={
        'generation_mode': 'template',
        'report_language': 'ch',
        'json_file': (BytesIO(json.dumps([sample_document()]).encode()), 'input.json'),
    })
    assert response.status_code == 202
    assert response.get_json()['status'] == 'running'
    job_id = ObjectId(response.get_json()['id'])
    with app.app_context():
        job = get_web_database()['report_jobs'].find_one({'_id': job_id})
        assert job['generation_mode'] == 'template'
        assert job['status'] == 'running'
        assert job['model'] == 'Fixed Template'
        assert job['report_language'] == 'en'
        assert job['effective_report_language'] == 'en'
        get_web_database()['report_jobs'].delete_one({'_id': job_id})
        get_web_database()['report_job_inputs'].delete_many({'job_id': job_id})


def test_create_enriched_weekly_job_requires_cve_review_selections():
    with app.app_context():
        job_id = create_job([{
            'collection': 'cve_review',
            'source_collection': 'cve',
            'selection_id': 'cve:test',
        }], 'review_selections', 'enriched_weekly', 'ch')
        job_object_id = ObjectId(job_id)
        try:
            job = get_web_database()['report_jobs'].find_one({'_id': job_object_id})
            assert job['generation_mode'] == 'enriched_weekly'
            assert job['status'] == 'queued'
            assert job['provider'] == 'Search API + llama-server'
            assert job['report_language'] == 'en'
            assert job['effective_report_language'] == 'en'
        finally:
            get_web_database()['report_jobs'].delete_one({'_id': job_object_id})
            get_web_database()['report_job_inputs'].delete_many({'job_id': job_object_id})

    with pytest.raises(ValueError, match='cve_review'):
        create_job([{
            'collection': 'avd_review',
            'source_collection': 'avd',
            'selection_id': 'avd:test',
        }], 'review_selections', 'enriched_weekly')
    with pytest.raises(ValueError, match='uploaded JSON'):
        create_job([sample_document()], 'upload', 'enriched_weekly')


def test_cancel_report_job_api(client, monkeypatch):
    authenticate(client)
    monkeypatch.setattr('reports.routes.start_job', lambda app, job_id: None)
    response = client.post('/api/reports', data={
        'json_file': (BytesIO(json.dumps([sample_document()]).encode()), 'input.json'),
    })
    assert response.status_code == 202
    job_id = response.get_json()['id']

    cancel = client.post(f'/api/reports/{job_id}/cancel')
    assert cancel.status_code == 200
    assert cancel.get_json()['status'] == 'cancelled'
    with app.app_context():
        job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
        assert job['status'] == 'cancelled'
        get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id)})
        get_web_database()['report_job_inputs'].delete_many({'job_id': ObjectId(job_id)})

    cancel_again = client.post(f'/api/reports/{job_id}/cancel')
    assert cancel_again.status_code == 400


def test_delete_report_job_api(client, monkeypatch):
    authenticate(client)
    monkeypatch.setattr('reports.routes.start_job', lambda app, job_id: None)
    response = client.post('/api/reports', data={
        'json_file': (BytesIO(json.dumps([sample_document()]).encode()), 'input.json'),
    })
    assert response.status_code == 202
    job_id = response.get_json()['id']

    delete_active = client.delete(f'/api/reports/{job_id}')
    assert delete_active.status_code == 400
    assert 'Cancel' in delete_active.get_json()['error']

    cancel = client.post(f'/api/reports/{job_id}/cancel')
    assert cancel.status_code == 200

    deleted = client.delete(f'/api/reports/{job_id}')
    assert deleted.status_code == 200
    assert deleted.get_json()['deleted'] is True
    with app.app_context():
        assert get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)}) is None
        assert get_web_database()['report_job_inputs'].count_documents({'job_id': ObjectId(job_id)}) == 0

    delete_again = client.delete(f'/api/reports/{job_id}')
    assert delete_again.status_code == 404


def test_run_job_exits_when_job_already_cancelled(tmp_path, monkeypatch):
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job_id = create_job([sample_document()], 'test', 'template')
            get_web_database()['report_jobs'].update_one(
                {'_id': ObjectId(job_id)},
                {'$set': {'status': 'cancelled'}},
            )
            run_job(app, job_id)
            job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'cancelled'
            assert 'report' not in job
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root
            get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id)})


def test_report_preview_and_download_render_structured_report_and_remove_legacy_html(client):
    authenticate(client)
    report = {
        'title': 'Cybersecurity Report',
        'executive_summary': 'Live report',
        'trends': [],
        'recommendations': [],
        'highlights': [],
    }
    with app.app_context():
        job_id = get_web_database()['report_jobs'].insert_one({
            'status': 'completed',
            'source_count': 0,
            'generation_mode': 'template',
            'effective_report_language': 'en',
            'report': report,
            'html': '<!doctype html><title>Stored report</title>',
            'html_updated_at': 'old',
            'html_path': 'old.html',
        }).inserted_id
    try:
        preview = client.get(f'/reports/{job_id}/preview')
        download = client.get(f'/reports/{job_id}/download')
        assert preview.status_code == 200
        assert b'Live report' in preview.data
        assert b'Stored report' not in preview.data
        assert download.status_code == 200
        assert 'attachment;' in download.headers['Content-Disposition']
        with app.app_context():
            stored = get_web_database()['report_jobs'].find_one({'_id': job_id})
            assert 'html' not in stored
            assert 'html_updated_at' not in stored
            assert 'html_path' not in stored
    finally:
        with app.app_context():
            get_web_database()['report_jobs'].delete_one({'_id': job_id})


def test_report_translation_api_validates_requests_and_reuses_running_translation(client):
    authenticate(client)
    report = {
        'title': 'Cybersecurity Report',
        'executive_summary': 'Live report',
        'trends': [],
        'recommendations': [],
        'highlights': [],
    }
    with app.app_context():
        job_id = get_web_database()['report_jobs'].insert_one({
            'status': 'completed',
            'source_count': 0,
            'generation_mode': 'template',
            'effective_report_language': 'en',
            'report': report,
        }).inserted_id
        active_translation_id = get_web_database()['report_jobs'].insert_one({
            'status': 'running',
            'source_count': 0,
            'generation_mode': 'template',
            'input_source': 'translation',
            'translated_from_job_id': job_id,
            'report_language': 'zh',
        }).inserted_id
        incomplete_id = get_web_database()['report_jobs'].insert_one({
            'status': 'running',
            'source_count': 0,
            'generation_mode': 'template',
        }).inserted_id
    try:
        invalid = client.post(f'/api/reports/{job_id}/translations', json={'language': 'en'})
        assert invalid.status_code == 400

        active = client.post(f'/api/reports/{job_id}/translations', json={'language': 'zh'})
        assert active.status_code == 202
        assert active.get_json()['status'] == 'running'
        assert active.get_json()['id'] == str(active_translation_id)

        rejected = client.post(f'/api/reports/{incomplete_id}/translations', json={'language': 'ch'})
        assert rejected.status_code == 400
    finally:
        with app.app_context():
            get_web_database()['report_jobs'].delete_many({
                '_id': {'$in': [job_id, active_translation_id, incomplete_id]},
            })


def test_report_translation_worker_stores_translated_variant_and_render_uses_language(client):
    authenticate(client)
    report = {
        'title': 'Cybersecurity Report',
        'executive_summary': 'Live report',
        'trends': [],
        'recommendations': [],
        'highlights': [],
        'template_mode': True,
    }
    with app.app_context():
        source_job_id = get_web_database()['report_jobs'].insert_one({
            'status': 'completed',
            'source_count': 0,
            'generation_mode': 'template',
            'effective_generation_mode': 'template',
            'report_language': 'en',
            'effective_report_language': 'en',
            'report': report,
        }).inserted_id
        translation_job_id = get_web_database()['report_jobs'].insert_one({
            'status': 'queued',
            'source_count': 0,
            'generation_mode': 'template',
            'effective_generation_mode': 'template',
            'input_source': 'translation',
            'translated_from_job_id': source_job_id,
            'report_language': 'zh',
            'effective_report_language': 'zh',
        }).inserted_id
        run_report_translation(app, str(translation_job_id), client=EchoTranslationClient())
        stored = get_web_database()['report_jobs'].find_one({'_id': translation_job_id})
        assert stored['status'] == 'completed'
        assert stored['report']['title'] == '網絡安全 Report'
        assert stored['html']
        assert stored['html_updated_at']
        assert b'lang="zh-Hant"' in stored['html'].encode()
        assert '即時報告'.encode() in stored['html'].encode()
    try:
        preview = client.get(f'/reports/{translation_job_id}/preview')
        download = client.get(f'/reports/{translation_job_id}/download')

        assert preview.status_code == 200
        assert preview.data == stored['html'].encode()
        assert b'lang="zh-Hant"' in preview.data
        assert '即時報告'.encode() in preview.data
        assert download.status_code == 200
        assert f'report-{translation_job_id}-zh.html' in download.headers['Content-Disposition']

        listed = client.get('/api/reports')
        assert listed.status_code == 200
        with app.app_context():
            still_stored = get_web_database()['report_jobs'].find_one({'_id': translation_job_id})
            assert still_stored['html']
            assert still_stored['html_updated_at']
    finally:
        with app.app_context():
            get_web_database()['report_jobs'].delete_many({
                '_id': {'$in': [source_job_id, translation_job_id]},
            })


def test_report_translation_worker_stores_simplified_chinese_html(client):
    authenticate(client)
    report = {
        'title': 'Cybersecurity Report',
        'executive_summary': 'Live report',
        'trends': [],
        'recommendations': [],
        'highlights': [],
        'template_mode': True,
    }
    with app.app_context():
        source_job_id = get_web_database()['report_jobs'].insert_one({
            'status': 'completed',
            'source_count': 0,
            'generation_mode': 'template',
            'effective_generation_mode': 'template',
            'report_language': 'en',
            'effective_report_language': 'en',
            'report': report,
        }).inserted_id
        translation_job_id = get_web_database()['report_jobs'].insert_one({
            'status': 'queued',
            'source_count': 0,
            'generation_mode': 'template',
            'effective_generation_mode': 'template',
            'input_source': 'translation',
            'translated_from_job_id': source_job_id,
            'report_language': 'ch',
            'effective_report_language': 'ch',
        }).inserted_id
        run_report_translation(app, str(translation_job_id), client=EchoTranslationClient())
        stored = get_web_database()['report_jobs'].find_one({'_id': translation_job_id})
        assert stored['status'] == 'completed'
        assert stored['html']
        assert b'lang="zh-Hans"' in stored['html'].encode()
        assert '执行摘要' in stored['html']
        assert '即時報告' in stored['html']
    try:
        preview = client.get(f'/reports/{translation_job_id}/preview')
        assert preview.status_code == 200
        assert preview.data == stored['html'].encode()
        assert b'lang="zh-Hans"' in preview.data
    finally:
        with app.app_context():
            get_web_database()['report_jobs'].delete_many({
                '_id': {'$in': [source_job_id, translation_job_id]},
            })


def test_source_report_preview_uses_completed_translation_html(client):
    authenticate(client)
    report = {
        'title': 'Cybersecurity Report',
        'executive_summary': 'Live report',
        'trends': [],
        'recommendations': [],
        'highlights': [],
        'template_mode': True,
    }
    with app.app_context():
        source_job_id = get_web_database()['report_jobs'].insert_one({
            'status': 'completed',
            'source_count': 0,
            'generation_mode': 'template',
            'effective_generation_mode': 'template',
            'report_language': 'en',
            'effective_report_language': 'en',
            'report': report,
        }).inserted_id
        translation_job_id = get_web_database()['report_jobs'].insert_one({
            'status': 'queued',
            'source_count': 0,
            'generation_mode': 'template',
            'effective_generation_mode': 'template',
            'input_source': 'translation',
            'translated_from_job_id': source_job_id,
            'report_language': 'zh',
            'effective_report_language': 'zh',
        }).inserted_id
        run_report_translation(app, str(translation_job_id), client=EchoTranslationClient())
        stored = get_web_database()['report_jobs'].find_one({'_id': translation_job_id})
    try:
        preview = client.get(f'/reports/{source_job_id}/preview?language=zh')
        assert preview.status_code == 200
        assert preview.data == stored['html'].encode()
    finally:
        with app.app_context():
            get_web_database()['report_jobs'].delete_many({
                '_id': {'$in': [source_job_id, translation_job_id]},
            })


def test_running_report_preview_renders_stored_item_results(client):
    authenticate(client)
    with app.app_context():
        job_id = get_web_database()['report_jobs'].insert_one({
            'status': 'running',
            'source_count': 2,
            'processed_count': 1,
            'generation_mode': 'template',
            'report_language': 'en',
            'effective_report_language': 'en',
        }).inserted_id
        get_web_database()['report_job_results'].insert_one({
            'job_id': job_id,
            'position': 0,
            'highlight': {'title': 'Live item', 'summary': 'Live progress summary'},
            'recommendations': ['Apply update.'],
        })
    try:
        response = client.get(f'/reports/{job_id}/preview')
        assert response.status_code == 200
        assert b'Live progress summary' in response.data
        assert client.get(f'/reports/{job_id}/download').status_code == 404
    finally:
        with app.app_context():
            get_web_database()['report_jobs'].delete_one({'_id': job_id})
            get_web_database()['report_job_results'].delete_many({'job_id': job_id})


def test_report_job_logs_endpoint_returns_pipeline_logs(client):
    authenticate(client)
    with app.app_context():
        job_id = get_web_database()['report_jobs'].insert_one({
            'status': 'running',
            'source_count': 1,
            'pipeline_logs': ['Starting job.', 'Halfway done.'],
            'progress_percent': 50,
            'status_message': 'Halfway done.',
        }).inserted_id
    try:
        response = client.get(f'/api/reports/{job_id}/logs')
        assert response.status_code == 200
        body = response.get_json()
        assert body['logs'] == ['Starting job.', 'Halfway done.']

        listed = client.get('/api/reports')
        assert listed.status_code == 200
        job = next(item for item in listed.get_json()['data'] if item['id'] == str(job_id))
        assert job['progress_percent'] == 50
        assert job['status_message'] == 'Halfway done.'
        assert 'pipeline_logs' not in job
    finally:
        with app.app_context():
            get_web_database()['report_jobs'].delete_one({'_id': job_id})


def test_legacy_html_only_report_is_not_served_and_is_cleaned_up(client):
    authenticate(client)
    with app.app_context():
        job_id = get_web_database()['report_jobs'].insert_one({
            'status': 'completed',
            'html': '<p>legacy only</p>',
        }).inserted_id
    try:
        response = client.get(f'/reports/{job_id}/preview')
        assert response.status_code == 404
        with app.app_context():
            assert 'html' not in get_web_database()['report_jobs'].find_one({'_id': job_id})
    finally:
        with app.app_context():
            get_web_database()['report_jobs'].delete_one({'_id': job_id})


def test_template_report_job_stores_structured_report_without_html(tmp_path):
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job_id = create_job([sample_document()], 'test', 'template')
            run_job(app, job_id)
            job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'completed'
            assert 'html_path' not in job
            assert 'html' not in job
            assert job['report']['title'] == 'Cybersecurity Report'
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root
            get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id)})


def test_template_report_job_renders_without_ai_provider(tmp_path):
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job_id = create_job( [sample_document()], 'test', 'template')
            run_job(app, job_id)
            job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'completed'
            assert job['generation_mode'] == 'template'
            assert job['model'] == 'Fixed Template'
            assert 'usage' not in job
            assert 'html_path' not in job
            assert 'html' not in job
            assert job['report']['highlights'][0]['summary'] == 'Evidence-based description.'
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root
            get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id)})


def test_template_report_jobs_run_concurrently(monkeypatch):
    barrier = threading.Barrier(2)
    original_load = report_jobs._load_input_details

    def synchronized_load(item):
        barrier.wait(timeout=2)
        return original_load(item)

    monkeypatch.setattr('reports.runner._load_input_details', synchronized_load)
    with app.app_context():
        job_ids = [
            create_job([sample_document(index)], 'test', 'template')
            for index in (1, 2)
        ]

    threads = [
        threading.Thread(target=run_template_job, args=(app, job_id))
        for job_id in job_ids
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=3)
        assert not thread.is_alive()

    with app.app_context():
        jobs = [
            get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            for job_id in job_ids
        ]
        assert [job['status'] for job in jobs] == ['completed', 'completed']


def test_template_report_job_records_failure(monkeypatch):
    monkeypatch.setattr(
        'reports.runner.generate_template_report_data',
        lambda records: (_ for _ in ()).throw(ValueError('Template generation failed.')),
    )
    with app.app_context():
        job_id = create_job([sample_document()], 'test', 'template')

    run_template_job(app, job_id)

    with app.app_context():
        job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
        assert job['status'] == 'failed'
        assert job['error'] == 'Template generation failed.'
        assert job['status_message'] == 'Template generation failed.'
        assert get_web_database()['report_job_inputs'].count_documents({
            'job_id': ObjectId(job_id),
        }) == 0


def test_finalize_item_uses_source_record_title():
    result = {
        'highlight': {'summary': 'Summary'},
        'recommendations': [],
    }
    finalized = _finalize_item_result(
        result,
        {'test': {'description': 'evidence'}},
        'ignored-id',
        1,
        {'title': 'Source Title'},
    )
    assert finalized['highlight']['title'] == 'Source Title'


def test_assemble_report_uses_fixed_title():
    final_data = {
        'title': 'AI Title Should Be Replaced',
        'executive_summary': 'Summary',
        'trends': [],
        'recommendations': [],
    }
    item_results = [{'highlight': {'title': 'Item', 'summary': 'x'}, 'recommendations': []}]
    report = _assemble_report(final_data, item_results, 'zh')
    assert report['title'] == '網絡安全報告'


def test_rendered_report_includes_item_table(tmp_path):
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job = {
                'source_count': 1,
                'generation_mode': 'template',
                'effective_report_language': 'en',
            }
            report = {
                'title': 'Cybersecurity Report',
                'executive_summary': 'Summary',
                'trends': [],
                'recommendations': [],
                'highlights': [{
                    'title': 'CVE-2024-1',
                    'summary': 'Details',
                    'table': {
                        'caption': 'Affected versions',
                        'headers': ['Product', 'Status'],
                        'rows': [['Widget', 'Affected']],
                    },
                }],
            }
            html = _render_job_html(job, report)
            assert 'Affected versions' in html
            assert '<table class="item-table">' in html
            assert 'Widget' in html
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root


def test_rendered_enriched_report_uses_cards_and_short_summary():
    with app.app_context():
        report = {
            'title': 'Weekly Cybersecurity Intelligence Report',
            'executive_summary': {
                'key_findings': [
                    '1 vulnerability reviewed.',
                    'Overall risk: Critical.',
                    'Affected products: Acme Widget.',
                    'Patch Critical and High items first.',
                ],
            },
            'vulnerability_detail_table': {
                'rows': [{
                    'cve_id': 'CVE-2026-7000',
                    'card_anchor': 'card-cve-2026-7000-acme-widget',
                    'title': 'Acme Widget RCE',
                    'vendor': 'Acme',
                    'product': 'Widget',
                    'severity': 'Critical',
                    'priority_score': 99,
                    'patch_priority': 'Critical',
                    'what_happened': 'Acme Widget has a remote code execution vulnerability.\nSecond paragraph.',
                    'why_matters': 'Remote code execution can affect internet-facing systems.',
                    'how_to_respond': 'Upgrade to version 2.0.',
                    'source_urls': ['https://acme.example/advisory'],
                }],
            },
        }
        html = _render_job_html({
            'source_count': 1,
            'generation_mode': 'enriched_weekly',
            'effective_report_language': 'en',
        }, report)

        assert '<h2>Vulnerability Cards</h2>' in html
        assert 'id="card-cve-2026-7000-acme-widget"' in html
        assert '<table class="vulnerability-card"' in html
        assert '<br>' in html
        assert 'Second paragraph.' in html
        assert 'href="#card-cve-2026-7000-acme-widget">CVE-2026-7000 | Acme | Widget</a>' in html
        assert '1 vulnerability reviewed.' in html
        assert 'Overall risk: Critical.' in html
        assert 'Affected products: Acme Widget.' in html
        assert 'Vulnerability Navigation' not in html
        assert '&lt;a href' not in html
        assert 'Priority' not in html
        assert 'Appendix' not in html
        assert 'Weekly Risk Trend' not in html
        assert 'Remediation Playbook' not in html


def test_rendered_template_report_includes_blank_sections_table_and_newsletter(tmp_path):
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            report = generate_template_report_data([{
                'title': 'Template advisory',
                'status': 'HIGH',
                'source': {'detail_url': 'https://example.com/source'},
                'details': {
                    'summary': 'Newsletter overview.',
                    'affected_products': ['Product A'],
                    'solution': 'Apply update.',
                    'references': ['https://example.com/reference'],
                },
            }])
            html = _render_job_html({
                'source_count': 1,
                'generation_mode': 'template',
                'effective_report_language': 'en',
            }, report)

            assert '<h2>Executive Summary</h2>' in html
            assert '<h2>Trends</h2>' in html
            assert '<th>Title</th><th>Severity</th><th>Source</th>' in html
            assert '<a href="https://example.com/source" rel="noopener">' in html
            assert '<h2>Item Summaries</h2>' in html
            assert 'Newsletter overview.' in html
            assert 'Product A' in html
            assert 'Apply update.' in html
            assert 'Strategic Recommendations' not in html
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root

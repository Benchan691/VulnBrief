import base64
import json
import threading
import time
from io import BytesIO

import pytest
import requests
import report_harness
from bson import ObjectId

from app import app
from mongo import get_web_database
from company_ai_auth_cache import clear_auth_state_for_tests, invalidate
from report_harness import (
    CompanyAIProvider,
    CompanyAILoginLimitExceeded,
    ITEM_SCHEMA,
    ProviderError,
    _assemble_report,
    _finalize_item_result,
    _render_job_html,
    compact_details,
    compact_document,
    cancel_job,
    create_job,
    generate_final_data,
    generate_item_data,
    generate_report_data,
    generate_template_report_data,
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
        'type': 'test',
        'title': f'Vulnerability {index}',
        'status': 'HIGH',
        'details': {
            'test': {
                'description': 'Evidence-based description.',
                'affected_products': ['Product A'],
                'reference_links': ['https://example.com'],
                'raw': {'large': 'must be removed'},
            },
        },
        'source': {'provider': 'test'},
    }


class FakeProvider:
    max_output = 500

    def __init__(self):
        self.calls = 0

    def create_room(self, prime_prompt=None):
        return 'fake-room'

    def delete_room(self):
        return None

    def complete_json(self, system_prompt, user_prompt):
        self.calls += 1
        if 'Input records:' in user_prompt:
            return {'records': [{'title': 'Reduced vulnerability evidence'}]}, {}
        return {
            'title': 'Cybersecurity Report',
            'executive_summary': 'Summary.',
            'highlights': [{
                'title': 'Vulnerability 1',
                'code': 'CVE-TEST',
                'severity': 'HIGH',
                'summary': 'Evidence summary.',
                'affected': ['Product A'],
                'references': ['https://example.com'],
            }],
            'trends': [],
            'recommendations': ['Apply updates.'],
        }, {'total_tokens': 100}


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


def test_generation_batches_oversized_input_and_validates_output():
    provider = FakeProvider()
    report, usage = generate_report_data(
        provider,
        [{'description': 'x' * 12000} for _ in range(5)],
        7000,
    )
    assert report['title'] == 'Cybersecurity Report'
    assert usage['total_tokens'] == 100
    assert provider.calls > 1


def test_ai_generation_prompts_for_selected_language():
    class CapturingProvider(FakeProvider):
        def __init__(self):
            super().__init__()
            self.system_prompt = None

        def complete_json(self, system_prompt, user_prompt):
            self.system_prompt = system_prompt
            return super().complete_json(system_prompt, user_prompt)

    provider = CapturingProvider()
    generate_report_data(provider, [sample_document()], 7000, 'zh')

    assert 'Traditional Chinese' in provider.system_prompt


def test_item_generation_retries_with_corrective_prompt():
    class CorrectingProvider:
        def __init__(self):
            self.prompts = []

        def complete_json(self, system_prompt, user_prompt):
            self.prompts.append(user_prompt)
            if len(self.prompts) == 1:
                return {'wrong': True}, {}
            return {
                'highlight': {'summary': 'Summary'},
                'recommendations': [],
            }, {}

    provider = CorrectingProvider()
    result, _ = generate_item_data(provider, {'description': 'evidence'}, 'review-1', 'en', 2)

    assert result['highlight']['title'] == 'review-1'
    assert provider.prompts[1].startswith('The JSON above is invalid.\n\nError:\n')
    assert "'highlight' is a required property" in provider.prompts[1]
    assert 'Review details:' not in provider.prompts[1]


def test_company_ai_item_retry_sends_only_validation_error():
    class ConversationalCorrectingProvider:
        retains_conversation_context = True

        def __init__(self):
            self.prompts = []

        def complete_json(self, system_prompt, user_prompt):
            self.prompts.append(user_prompt)
            if len(self.prompts) == 1:
                return {'wrong': True}, {}
            return {
                'highlight': {'summary': 'Summary'},
                'recommendations': [],
            }, {}

    provider = ConversationalCorrectingProvider()
    generate_item_data(provider, {'description': 'secret evidence'}, 'review-1', 'en', 2)

    assert provider.prompts[1].startswith('The JSON above is invalid.\n\nError:\n')
    assert "'highlight' is a required property" in provider.prompts[1]
    assert 'secret evidence' not in provider.prompts[1]
    assert 'Review details:' not in provider.prompts[1]


def test_item_retry_uses_provider_configured_error_message():
    class ConfiguredProvider:
        retains_conversation_context = True
        json_error_message = 'Configured correction: ${error}'

        def __init__(self):
            self.prompts = []

        def complete_json(self, system_prompt, user_prompt):
            self.prompts.append(user_prompt)
            if len(self.prompts) == 1:
                return {'wrong': True}, {}
            return {
                'highlight': {'title': 'Corrected', 'summary': 'Summary'},
                'recommendations': [],
            }, {}

    provider = ConfiguredProvider()
    generate_item_data(provider, {'description': 'evidence'}, 'review-1', 'en', 1)

    assert provider.prompts[1].startswith('Configured correction: ')
    assert '${error}' not in provider.prompts[1]


def test_template_generation_maps_source_fields_and_counts():
    report = generate_template_report_data([
        {
            'code': 'CVE-TEST-1',
            'title': 'First vulnerability',
            'status': 'HIGH',
            'details': {
                'summary': 'Source summary.',
                'affected_products': ['Product A', 'product a'],
                'references': {'advisory': 'https://example.com/advisory'},
                'solution': ['Apply update.', 'apply update.'],
            },
        },
        {
            'code': 'CVE-TEST-2',
            'status': 'MEDIUM',
            'details': {
                'description': 'Second source description.',
                'systems_affected': 'Product B',
                'recommendation': 'Restrict access.',
            },
        },
    ])

    assert report['title'] == 'Cybersecurity Report'
    assert report['highlights'][0] == {
        'title': 'First vulnerability',
        'code': 'CVE-TEST-1',
        'severity': 'HIGH',
        'summary': 'Source summary.',
        'affected': ['Product A'],
        'references': ['https://example.com/advisory'],
    }
    assert report['highlights'][1]['title'] == 'CVE-TEST-2'
    assert report['recommendations'] == ['Apply update.', 'Restrict access.']
    assert 'Severity or status data is available for 2 of 2 records.' in report['executive_summary']
    assert 'Affected product or system data is available for 2 of 2 records.' in report['executive_summary']
    assert 'Remediation guidance is available for 2 of 2 records.' in report['executive_summary']
    assert report['trends'] == [
        'Severity or status coverage: 2 of 2 records. Distribution: HIGH: 1, MEDIUM: 1.',
        (
            'Affected product or system coverage: 2 of 2 records. '
            'Most frequently affected: Product A: 1, Product B: 1.'
        ),
        'Remediation guidance coverage: 2 of 2 records.',
        'Reference coverage: 1 of 2 records.',
    ]


def test_template_generation_maps_cnnvd_fields():
    report = generate_template_report_data([{
        'title': 'Spring Security 资源管理错误漏洞',
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
    assert highlight['affected'] == ['Spring']
    assert highlight['references'] == ['链接:https://nvd.nist.gov/vuln/detail/CVE-2026-40988']
    assert report['recommendations'] == ['https://spring.io/security/cve-2026-40988']


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
    assert report['highlights'][0]['title'] == 'Cisco Advisory'


def test_create_job_requires_at_least_one_record():
    with pytest.raises(ValueError, match='At least one vulnerability record is required'):
        create_job([], 'test')


def test_template_generation_uses_missing_field_fallbacks():
    report = generate_template_report_data([{'details': {}}])

    assert report['highlights'][0]['title'] == 'Vulnerability record 1'
    assert report['highlights'][0]['summary'] == (
        'No description or summary was provided in the source record.'
    )
    assert report['recommendations'] == [
        'No recommendations were provided in the source records.',
    ]
    assert report['trends'] == [
        'Severity or status coverage: 0 of 1 records.',
        'Affected product or system coverage: 0 of 1 records.',
        'Remediation guidance coverage: 0 of 1 records.',
        'Reference coverage: 0 of 1 records.',
    ]


def company_ai_config():
    return {
        'COMPANY_AI_BASE_URL': 'https://company.example',
        'COMPANY_AI_USERNAME': 'owner',
        'COMPANY_AI_PASSWORD': 'password',
        'COMPANY_AI_START_PROMPT': 'initial prompt',
        'COMPANY_AI_SUMMARY_PROMPT': (
            'Write the overall summary in ${language}. '
            'Return valid JSON only.'
        ),
        'COMPANY_AI_PUBLIC_KEY_B64': (
            'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD0BCSaKhAeA8kQS4pK7QGaFwZ4'
            'MJCdU9fUdbYVALts6U+TEvfWXsyRcLQfmHq3bSl3QE2CGbgt/tKznKWS9ODyUwpf'
            'z7/+zAuDVlPD4opHy+ni9zbxefsEN4VtyFoTBiO7BAAxWjPXhHir6hZUcF5ZTJsW'
            '43wTdcdajuqxn67mUwIDAQAB'
        ),
        'COMPANY_AI_SIGN_SECRET': 'secret',
        'COMPANY_AI_API_TIMEZONE': 'Asia/Shanghai',
        'COMPANY_AI_SSE_DELAY_SECONDS': 0,
        'COMPANY_AI_MODEL': 'company-model',
        'COMPANY_AI_OWNER_ACCOUNT': 'owner',
        'COMPANY_AI_PLATFORM_ID': 5,
        'COMPANY_AI_QA_TYPE': 0,
        'COMPANY_AI_FROM_SOURCE': 'normal_chat',
        'COMPANY_AI_USE_THINK': True,
        'COMPANY_AI_USER_PROMPT': '',
        'COMPANY_AI_DATASET_IDS': [],
        'COMPANY_AI_FILE_IDS': [],
        'COMPANY_AI_MAX_OUTPUT_TOKENS': 500,
        'COMPANY_AI_TIMEOUT_SECONDS': 10,
        'COMPANY_AI_RETRIES': 0,
        'COMPANY_AI_AUTH_TTL_SECONDS': 3600,
        'COMPANY_AI_LOGIN_MAX_FAILURES': 3,
    }


@pytest.fixture(autouse=True)
def reset_company_ai_auth_cache():
    clear_auth_state_for_tests()
    yield
    clear_auth_state_for_tests()


def test_company_ai_sse_decodes_utf8_chinese_bytes(monkeypatch):
    answer = '```json\n' + json.dumps(
        {
            'highlight': {'title': '漏洞摘要', 'summary': '繁體中文測試'},
            'recommendations': ['建議措施'],
        },
        ensure_ascii=False,
    ) + '\n```'
    message_line = ('data: ' + json.dumps({
        'event': 'message',
        'answer_content': answer,
    }, ensure_ascii=False)).encode('utf-8')

    class FakeStream:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def raise_for_status(self):
            return None

        def iter_lines(self, **kwargs):
            return iter([
                message_line,
                b'data: {"event":"message_end"}',
            ])

    monkeypatch.setattr('report_harness.requests.get', lambda *args, **kwargs: FakeStream())
    monkeypatch.setattr('report_harness.requests.post', lambda *args, **kwargs: type('R', (), {'raise_for_status': lambda self: None})())
    provider = CompanyAIProvider(company_ai_config())
    provider.conversation_id = 'conversation-id'
    provider.system_token = 'Bearer system-token'
    provider.bot_token = 'Bearer bot-token'
    result, _ = provider.complete_json('system', 'user')
    assert result['highlight']['title'] == '漏洞摘要'
    assert result['recommendations'] == ['建議措施']


def test_company_ai_provider_collects_sse_and_parses_fenced_json(monkeypatch):
    captured = {}
    order = []

    class FakeStream:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def raise_for_status(self):
            return None

        def iter_lines(self, **kwargs):
            return iter([
                'data: {"event":"message","answer_content":"```json\\n{\\"ok\\":"}',
                'data: {"event":"message","answer_content":" true}\\n```"}',
                'data: {"event":"message_end"}',
            ])

    class FakeResponse:
        def raise_for_status(self):
            return None

    def fake_get(url, **kwargs):
        order.append('sse')
        captured['get_url'] = url
        captured['get_kwargs'] = kwargs
        return FakeStream()

    def fake_post(url, **kwargs):
        order.append('post')
        captured['post_url'] = url
        captured['post_kwargs'] = kwargs
        return FakeResponse()

    monkeypatch.setattr('report_harness.requests.get', fake_get)
    monkeypatch.setattr('report_harness.requests.post', fake_post)
    provider = CompanyAIProvider(company_ai_config())
    provider.conversation_id = 'conversation-id'
    provider.system_token = 'Bearer system-token'
    provider.bot_token = 'Bearer bot-token'
    result, usage = provider.complete_json('system', 'user')

    assert result == {'ok': True}
    assert usage == {}
    assert captured['get_url'].endswith('/smartbot/openapi/im/sse/createSse')
    assert captured['get_kwargs']['params']['uid'] == 'conversation-id'
    assert captured['post_url'].endswith('/smartbot/openapi/im/biz/createChat')
    assert captured['post_kwargs']['json']['content'] == 'system\n\nuser'
    assert captured['post_kwargs']['json']['modelName'] == 'company-model'
    assert captured['post_kwargs']['headers']['Authorization'] == 'Bearer bot-token'
    assert captured['post_kwargs']['headers']['x-authorization'] == 'Bearer system-token'
    assert order == ['sse', 'post']


def test_company_ai_signature_is_deterministic(monkeypatch):
    provider = CompanyAIProvider(company_ai_config())
    monkeypatch.setattr(provider, '_request_id', lambda: 'request-id')
    monkeypatch.setattr(provider, '_timestamp', lambda: '20260610120000')

    headers = provider._api_headers('/sys/login', {'username': 'owner', 'password': 'encrypted'})

    assert headers['requestId'] == 'request-id'
    assert headers['timestamp'] == '20260610120000'
    assert headers['signature'] == provider._signature(
        'request-id',
        '20260610120000',
        {'username': 'owner', 'password': 'encrypted'},
        '/sys/login',
    )


def test_company_ai_encrypts_password_with_configured_public_key():
    provider = CompanyAIProvider(company_ai_config())

    encrypted = provider._encrypt_password()

    assert encrypted != 'password'
    assert len(base64.b64decode(encrypted)) == 128


def test_company_ai_authenticates_creates_and_deletes_room(monkeypatch):
    calls = []

    class FakeResponse:
        def __init__(self, body=None):
            self.body = body or {}

        def raise_for_status(self):
            return None

        def json(self):
            return self.body

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        if url.endswith('/api/sys/login'):
            return FakeResponse({'success': True, 'data': 'system-token'})
        return FakeResponse()

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse({'success': True, 'data': 'bot-token'})

    def fake_delete(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse({'success': True, 'data': True})

    monkeypatch.setattr('report_harness.requests.post', fake_post)
    monkeypatch.setattr('report_harness.requests.get', fake_get)
    monkeypatch.setattr('report_harness.requests.delete', fake_delete)
    monkeypatch.setattr('report_harness.uuid.uuid4', lambda: 'new-room')
    provider = CompanyAIProvider(company_ai_config())
    monkeypatch.setattr(provider, '_encrypt_password', lambda: 'encrypted')
    monkeypatch.setattr(provider, '_chat_once', lambda prompt: '')

    assert provider.create_room() == 'new-room'
    assert calls[0][0].endswith('/api/sys/login')
    assert calls[1][0].endswith('/api/sys/getBotToken')
    assert provider.system_token == 'Bearer system-token'
    assert provider.bot_token == 'Bearer bot-token'
    provider.delete_room()
    assert calls[2][0].endswith('/smartbot/openapi/im/biz/deleteChat/new-room')
    assert calls[2][1]['headers']['Authorization'] == 'Bearer bot-token'


def test_company_ai_tokens_are_reused_across_providers(monkeypatch):
    login_posts = []
    bot_token_gets = []

    class FakeResponse:
        def __init__(self, body=None, status_code=200):
            self.body = body or {}
            self.status_code = status_code

        def raise_for_status(self):
            return None

        def json(self):
            return self.body

    def fake_post(url, **kwargs):
        if url.endswith('/api/sys/login'):
            login_posts.append(url)
            return FakeResponse({'success': True, 'data': 'system-token'})
        return FakeResponse()

    def fake_get(url, **kwargs):
        if url.endswith('/api/sys/getBotToken'):
            bot_token_gets.append(url)
            return FakeResponse({'success': True, 'data': 'bot-token'})
        return FakeResponse()

    monkeypatch.setattr('report_harness.requests.post', fake_post)
    monkeypatch.setattr('report_harness.requests.get', fake_get)
    config = company_ai_config()
    first = CompanyAIProvider(config)
    second = CompanyAIProvider(config)
    monkeypatch.setattr(first, '_encrypt_password', lambda: 'encrypted')
    monkeypatch.setattr(second, '_encrypt_password', lambda: 'encrypted')
    monkeypatch.setattr(first, '_chat_once', lambda prompt: '')
    monkeypatch.setattr(second, '_chat_once', lambda prompt: '')

    first.create_room()
    second.create_room()

    assert len(login_posts) == 1
    assert len(bot_token_gets) == 1


def test_company_ai_tokens_refresh_after_ttl_expiry(monkeypatch):
    import company_ai_auth_cache as auth_cache

    times = [1000.0]
    monkeypatch.setattr(auth_cache.time, 'monotonic', lambda: times[0])

    login_posts = []

    class FakeResponse:
        def __init__(self, body=None, status_code=200):
            self.body = body or {}
            self.status_code = status_code

        def raise_for_status(self):
            return None

        def json(self):
            return self.body

    def fake_post(url, **kwargs):
        if url.endswith('/api/sys/login'):
            login_posts.append(url)
            return FakeResponse({'success': True, 'data': 'system-token'})
        return FakeResponse()

    def fake_get(url, **kwargs):
        if url.endswith('/api/sys/getBotToken'):
            return FakeResponse({'success': True, 'data': 'bot-token'})
        return FakeResponse()

    monkeypatch.setattr('report_harness.requests.post', fake_post)
    monkeypatch.setattr('report_harness.requests.get', fake_get)
    config = {**company_ai_config(), 'COMPANY_AI_AUTH_TTL_SECONDS': 60}
    provider = CompanyAIProvider(config)
    monkeypatch.setattr(provider, '_encrypt_password', lambda: 'encrypted')
    monkeypatch.setattr(provider, '_chat_once', lambda prompt: '')

    provider.create_room()
    times[0] = 1061.0
    provider.create_room()

    assert len(login_posts) == 2


def test_company_ai_send_message_retries_once_after_auth_error(monkeypatch):
    attempts = {'count': 0}

    class FakeResponse:
        def __init__(self, status_code=200, body=None):
            self.status_code = status_code
            self.body = body or {'success': True}

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.HTTPError(response=self)

        def json(self):
            return self.body

    def fake_post(url, **kwargs):
        if url.endswith('/biz/createChat'):
            attempts['count'] += 1
            if attempts['count'] == 1:
                return FakeResponse(status_code=401)
            return FakeResponse()
        if url.endswith('/api/sys/login'):
            return FakeResponse(body={'success': True, 'data': 'system-token'})
        return FakeResponse()

    def fake_get(url, **kwargs):
        if url.endswith('/api/sys/getBotToken'):
            return FakeResponse(body={'success': True, 'data': 'bot-token'})
        return FakeResponse()

    monkeypatch.setattr('report_harness.requests.post', fake_post)
    monkeypatch.setattr('report_harness.requests.get', fake_get)
    provider = CompanyAIProvider(company_ai_config())
    monkeypatch.setattr(provider, '_encrypt_password', lambda: 'encrypted')
    provider.create_room(prime_prompt='')
    provider._send_message('payload')
    assert attempts['count'] == 2


def test_company_ai_login_limit_blocks_after_max_failures(monkeypatch):
    login_posts = []

    class FakeResponse:
        def __init__(self, body=None, status_code=200):
            self.body = body or {'success': False}
            self.status_code = status_code

        def raise_for_status(self):
            return None

        def json(self):
            return self.body

    def fake_post(url, **kwargs):
        if url.endswith('/api/sys/login'):
            login_posts.append(url)
            return FakeResponse({'success': False})
        return FakeResponse()

    def fake_get(url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr('report_harness.requests.post', fake_post)
    monkeypatch.setattr('report_harness.requests.get', fake_get)
    config = {**company_ai_config(), 'COMPANY_AI_LOGIN_MAX_FAILURES': 3}
    provider = CompanyAIProvider(config)
    monkeypatch.setattr(provider, '_encrypt_password', lambda: 'encrypted')
    monkeypatch.setattr(provider, '_chat_once', lambda prompt: '')

    for _ in range(3):
        with pytest.raises(ProviderError):
            provider.create_room()

    with pytest.raises(CompanyAILoginLimitExceeded):
        provider.create_room()

    assert len(login_posts) == 3


def test_company_ai_login_failure_counter_resets_after_success(monkeypatch):
    login_results = [
        {'success': False},
        {'success': False},
        {'success': True, 'data': 'system-token'},
        {'success': False},
        {'success': True, 'data': 'system-token'},
    ]
    login_index = {'value': 0}

    class FakeResponse:
        def __init__(self, body=None, status_code=200):
            self.body = body or {}
            self.status_code = status_code

        def raise_for_status(self):
            return None

        def json(self):
            return self.body

    def fake_post(url, **kwargs):
        if url.endswith('/api/sys/login'):
            body = login_results[login_index['value']]
            login_index['value'] += 1
            return FakeResponse(body)
        return FakeResponse({'success': True})

    def fake_get(url, **kwargs):
        if url.endswith('/api/sys/getBotToken'):
            return FakeResponse({'success': True, 'data': 'bot-token'})
        return FakeResponse()

    monkeypatch.setattr('report_harness.requests.post', fake_post)
    monkeypatch.setattr('report_harness.requests.get', fake_get)
    config = {**company_ai_config(), 'COMPANY_AI_LOGIN_MAX_FAILURES': 3}
    provider = CompanyAIProvider(config)
    monkeypatch.setattr(provider, '_encrypt_password', lambda: 'encrypted')
    monkeypatch.setattr(provider, '_chat_once', lambda prompt: '')

    with pytest.raises(ProviderError):
        provider.create_room()
    with pytest.raises(ProviderError):
        provider.create_room()
    provider.create_room()
    invalidate(provider.base_url, provider.username)
    with pytest.raises(ProviderError):
        provider.create_room()
    provider.create_room()


def test_company_ai_provider_create_room_skips_priming_for_summary(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {'success': True, 'data': 'token'}

    monkeypatch.setattr(
        'report_harness.requests.post',
        lambda *args, **kwargs: FakeResponse(),
    )
    monkeypatch.setattr(
        'report_harness.requests.get',
        lambda *args, **kwargs: FakeResponse(),
    )
    provider = CompanyAIProvider(company_ai_config())
    monkeypatch.setattr(provider, '_encrypt_password', lambda: 'encrypted')
    chats = []
    monkeypatch.setattr(
        provider,
        '_chat_once',
        lambda prompt, wait_for_response=True: chats.append((prompt, wait_for_response)),
    )
    provider.create_room(prime_prompt='')
    assert chats == []
    provider.create_room()
    assert chats == [('initial prompt', True)]


def test_create_room_waits_for_and_ignores_priming_response(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {'success': True, 'data': 'token'}

    monkeypatch.setattr(
        'report_harness.requests.post',
        lambda *args, **kwargs: FakeResponse(),
    )
    monkeypatch.setattr(
        'report_harness.requests.get',
        lambda *args, **kwargs: FakeResponse(),
    )
    provider = CompanyAIProvider(company_ai_config())
    monkeypatch.setattr(provider, '_encrypt_password', lambda: 'encrypted')
    chats = []
    monkeypatch.setattr(provider, '_chat_once', lambda prompt: chats.append(prompt) or 'not json')
    provider.create_room()
    assert chats == ['initial prompt']


def test_company_ai_provider_rejects_stream_without_message_end(monkeypatch):
    class FakeStream:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def raise_for_status(self):
            return None

        def iter_lines(self, **kwargs):
            return iter(['data: {"event":"message","answer_content":"{}"}'])

    class FakeResponse:
        def raise_for_status(self):
            return None

    monkeypatch.setattr('report_harness.requests.get', lambda *args, **kwargs: FakeStream())
    monkeypatch.setattr('report_harness.requests.post', lambda *args, **kwargs: FakeResponse())

    with pytest.raises(ProviderError, match='message_end'):
        provider = CompanyAIProvider(company_ai_config())
        provider.conversation_id = 'conversation-id'
        provider.system_token = 'Bearer system'
        provider.bot_token = 'Bearer bot'
        provider.complete_json('system', 'user')


def test_company_ai_provider_wraps_timeout(monkeypatch):
    def timeout(*args, **kwargs):
        raise requests.Timeout('timed out')

    class FakeResponse:
        def raise_for_status(self):
            return None

    monkeypatch.setattr('report_harness.requests.get', timeout)
    monkeypatch.setattr('report_harness.requests.post', lambda *args, **kwargs: FakeResponse())

    with pytest.raises(ProviderError, match='timed out'):
        provider = CompanyAIProvider(company_ai_config())
        provider.conversation_id = 'conversation-id'
        provider.system_token = 'Bearer system'
        provider.bot_token = 'Bearer bot'
        provider.complete_json('system', 'user')


def test_company_ai_provider_rejects_malformed_json(monkeypatch):
    class FakeStream:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def raise_for_status(self):
            return None

        def iter_lines(self, **kwargs):
            return iter([
                'data: {"event":"message","answer_content":"not json"}',
                'data: {"event":"message_end"}',
            ])

    class FakeResponse:
        def raise_for_status(self):
            return None

    monkeypatch.setattr('report_harness.requests.get', lambda *args, **kwargs: FakeStream())
    monkeypatch.setattr('report_harness.requests.post', lambda *args, **kwargs: FakeResponse())

    with pytest.raises(ProviderError, match='invalid JSON'):
        provider = CompanyAIProvider(company_ai_config())
        provider.conversation_id = 'conversation-id'
        provider.system_token = 'Bearer system'
        provider.bot_token = 'Bearer bot'
        provider.complete_json('system', 'user')


def test_company_ai_provider_json_retry_sends_only_error(monkeypatch):
    prompts = []
    provider = CompanyAIProvider({**company_ai_config(), 'COMPANY_AI_RETRIES': 1})
    provider.conversation_id = 'conversation-id'
    provider.system_token = 'Bearer system'
    provider.bot_token = 'Bearer bot'

    def fake_chat(prompt):
        prompts.append(prompt)
        return 'not json' if len(prompts) == 1 else '{"ok": true}'

    monkeypatch.setattr(provider, '_chat_once', fake_chat)
    result, _ = provider.complete_json('system instructions', 'secret review details')

    assert result == {'ok': True}
    assert prompts[0] == 'system instructions\n\nsecret review details'
    assert prompts[1].startswith('The JSON above is invalid.\n\nError:\n')
    assert 'invalid JSON' in prompts[1]
    assert 'secret review details' not in prompts[1]


def test_reports_api_upload_and_authentication(client, monkeypatch):
    assert client.get('/reports').status_code == 302
    authenticate(client)
    monkeypatch.setattr('routes.report.start_job', lambda app, job_id: None)
    response = client.post('/api/reports', data={
        'json_file': (BytesIO(b'[]'), 'input.json'),
    })
    assert response.status_code == 400

    response = client.post('/api/reports', data={
        'json_file': (BytesIO(json.dumps([sample_document()]).encode()), 'input.json'),
    })
    assert response.status_code == 202
    assert response.get_json()['status'] == 'queued'
    job_id = ObjectId(response.get_json()['id'])
    with app.app_context():
        job = get_web_database()['report_jobs'].find_one({'_id': job_id})
        assert job['status'] == 'queued'
        assert job['generation_mode'] == 'company_ai'
        assert job['effective_generation_mode'] == 'company_ai'
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
        'Generation mode must be "company_ai" or "template".'
    )

    response = client.post('/api/reports', data={
        'generation_mode': 'ai',
        'json_file': (BytesIO(json.dumps([sample_document()]).encode()), 'input.json'),
    })
    assert response.status_code == 202
    job_id = ObjectId(response.get_json()['id'])
    with app.app_context():
        job = get_web_database()['report_jobs'].find_one({'_id': job_id})
        assert job['generation_mode'] == 'company_ai'
        get_web_database()['report_jobs'].delete_one({'_id': job_id})
        get_web_database()['report_job_inputs'].delete_many({'job_id': job_id})

    response = client.post('/api/reports', data={
        'generation_mode': 'company_ai',
        'report_language': 'invalid',
        'json_file': (BytesIO(json.dumps([sample_document()]).encode()), 'input.json'),
    })
    assert response.status_code == 400
    assert response.get_json()['error'] == 'Report language must be "en", "zh", or "ch".'

    response = client.post('/api/reports', data={
        'generation_mode': 'company_ai',
        'report_language': 'zh',
        'json_file': (BytesIO(json.dumps([sample_document()]).encode()), 'input.json'),
    })
    assert response.status_code == 202
    job_id = ObjectId(response.get_json()['id'])
    with app.app_context():
        job = get_web_database()['report_jobs'].find_one({'_id': job_id})
        assert job['generation_mode'] == 'company_ai'
        assert job['effective_generation_mode'] == 'company_ai'
        assert job['model'] == 'Shared AI Workers'
        assert job['provider'] == 'RabbitMQ + Atlas'
        assert job['report_language'] == 'zh'
        assert job['effective_report_language'] == 'zh'
        get_web_database()['report_jobs'].delete_one({'_id': job_id})
        get_web_database()['report_job_inputs'].delete_many({'job_id': job_id})

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


def test_cancel_report_job_api(client, monkeypatch):
    authenticate(client)
    monkeypatch.setattr('routes.report.start_job', lambda app, job_id: None)
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


def test_run_job_exits_when_job_already_cancelled(tmp_path, monkeypatch):
    monkeypatch.setattr('report_harness.CompanyAIProvider', lambda config: FakeProvider())
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


def test_run_job_stops_during_company_ai_wait(tmp_path, monkeypatch):
    def wait_then_cancel(references, timeout, should_continue=None):
        with app.app_context():
            get_web_database()['report_jobs'].update_one(
                {'_id': ObjectId(job_id_holder['id'])},
                {'$set': {'status': 'cancelled'}},
            )
        while should_continue is not None and should_continue():
            time.sleep(0.05)
        return [None] * len(references)

    job_id_holder = {}
    monkeypatch.setattr('company_ai_preprocessor.enqueue_report_items', lambda *args: [{}])
    monkeypatch.setattr('company_ai_preprocessor.wait_for_summaries', wait_then_cancel)
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job_id = create_job([sample_document()], 'test', 'company_ai')
            job_id_holder['id'] = job_id
            run_job(app, job_id)
            job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'cancelled'
            assert 'report' not in job
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root
            get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id_holder['id'])})


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


def test_running_report_preview_renders_stored_item_results(client):
    authenticate(client)
    with app.app_context():
        job_id = get_web_database()['report_jobs'].insert_one({
            'status': 'running',
            'source_count': 2,
            'processed_count': 1,
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


def test_report_job_stores_structured_report_without_html(tmp_path, monkeypatch):
    cached_item = {
        'highlight': {
            'title': 'Vulnerability 1',
            'summary': 'Evidence summary.',
            'affected': ['Product A'],
            'references': ['https://example.com'],
        },
        'recommendations': ['Apply updates.'],
    }
    _mock_company_ai_cache(monkeypatch, [cached_item])
    monkeypatch.setattr('report_harness.CompanyAIProvider', lambda config: FakeProvider())
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job_id = create_job( [sample_document()], 'test')
            run_job(app, job_id)
            job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'completed'
            assert 'html_path' not in job
            assert 'html' not in job
            assert job['report']['title'] == 'Cybersecurity Report'
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root
            get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id)})


def test_template_report_job_renders_without_ai_provider(tmp_path, monkeypatch):
    def fail_if_constructed(config):
        raise AssertionError('Template jobs must not construct an AI provider.')

    monkeypatch.setattr('report_harness.CompanyAIProvider', fail_if_constructed)
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


def test_template_report_job_bypasses_shared_worker_lock_and_lease(monkeypatch):
    monkeypatch.setattr(
        'report_harness._acquire_worker_lease',
        lambda owner: (_ for _ in ()).throw(AssertionError('Template must not acquire lease.')),
    )
    with app.app_context():
        job_id = create_job([sample_document()], 'test', 'template')

    completed = threading.Event()

    def execute():
        run_job(app, job_id)
        completed.set()

    with report_harness.WORKER_LOCK:
        thread = threading.Thread(target=execute)
        thread.start()
        assert completed.wait(timeout=2)
    thread.join(timeout=2)

    with app.app_context():
        job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
        assert job['status'] == 'completed'


def test_template_report_jobs_run_concurrently(monkeypatch):
    barrier = threading.Barrier(2)
    original_load = report_harness._load_input_details

    def synchronized_load(item):
        barrier.wait(timeout=2)
        return original_load(item)

    monkeypatch.setattr('report_harness._load_input_details', synchronized_load)
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
        'report_harness.generate_template_report_data',
        lambda records: (_ for _ in ()).throw(ValueError('Template generation failed.')),
    )
    with app.app_context():
        job_id = create_job([sample_document()], 'test', 'template')

    run_template_job(app, job_id)

    with app.app_context():
        job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
        assert job['status'] == 'failed'
        assert job['error'] == 'Template generation failed.'
        assert get_web_database()['report_job_inputs'].count_documents({
            'job_id': ObjectId(job_id),
        }) == 0


def _mock_company_ai_cache(monkeypatch, results):
    monkeypatch.setattr(
        'company_ai_preprocessor.enqueue_report_items',
        lambda items, language, config: [
            {'storage': 'upload', 'language': language, 'content_hash': f'hash-{index}'}
            for index, _ in enumerate(items)
        ],
    )
    monkeypatch.setattr(
        'company_ai_preprocessor.wait_for_summaries',
        lambda references, timeout, should_continue=None: (
            [
                {
                    'title': 'Cybersecurity Report',
                    'executive_summary': 'Queued final summary.',
                    'trends': [],
                    'recommendations': [],
                }
            ] if references and references[0].get('task_type') == 'final' else list(results)
        ),
    )
    monkeypatch.setattr(
        'company_ai_preprocessor.enqueue_final_summary',
        lambda item_results, language, config: {
            'storage': 'shared',
            'task_id': ObjectId(),
            'task_type': 'final',
            'language': language,
            'content_hash': 'final-hash',
        },
    )


def test_company_ai_report_job_uses_company_provider(tmp_path, monkeypatch):
    cached_item = {
        'highlight': {'title': 'Cached', 'summary': 'Summary'},
        'recommendations': [],
    }
    _mock_company_ai_cache(monkeypatch, [cached_item])
    monkeypatch.setattr('report_harness.CompanyAIProvider', lambda config: FakeProvider())
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job_id = create_job( [sample_document()], 'test', 'company_ai', 'ch')
            run_job(app, job_id)
            job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'completed'
            assert job['effective_generation_mode'] == 'company_ai'
            assert job['effective_report_language'] == 'ch'
            assert 'fallback_reason' not in job
            assert 'html' not in job
            html = _render_job_html(job, job['report'])
            assert '<html lang="zh-Hans">' in html
            assert '执行摘要' in html
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root
            get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id)})


def test_generate_final_data_uses_configured_summary_prompt():
    class CapturingProvider(FakeProvider):
        def __init__(self):
            super().__init__()
            self.system_prompt = None

        def complete_json(self, system_prompt, user_prompt):
            self.system_prompt = system_prompt
            return {
                'title': 'Cybersecurity Report',
                'executive_summary': 'Summary.',
                'trends': [],
                'recommendations': ['Apply updates.'],
            }, {}

    provider = CapturingProvider()
    config = {
        'COMPANY_AI_SUMMARY_PROMPT': (
            'Configured summary in ${language}.'
        ),
    }
    generate_final_data(
        provider,
        [{'highlight': {'title': 'Cached', 'summary': 'Summary'}, 'recommendations': []}],
        'zh',
        0,
        config,
    )

    assert provider.system_prompt == 'Configured summary in Traditional Chinese.'


def test_generate_final_data_uses_fixed_report_title():
    provider = FakeProvider()
    config = {'COMPANY_AI_SUMMARY_PROMPT': 'Summary in ${language}.'}
    result, _ = generate_final_data(
        provider,
        [{'highlight': {'title': 'Ignored', 'summary': 'Summary'}, 'recommendations': []}],
        'zh',
        0,
        config,
    )
    assert result['title'] == '網絡安全報告'


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


def test_item_schema_accepts_optional_table():
    validate(instance={
        'highlight': {
            'summary': 'Summary',
            'table': {
                'headers': ['Product', 'Version'],
                'rows': [['App', '1.0']],
            },
        },
        'recommendations': [],
    }, schema=ITEM_SCHEMA)


def test_rendered_report_includes_item_table(tmp_path):
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job = {
                'source_count': 1,
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


def test_report_job_queues_final_summary_without_opening_provider_room(tmp_path, monkeypatch):
    cached_item = {
        'highlight': {'title': 'Cached', 'summary': 'Summary'},
        'recommendations': [],
    }

    class TrackingProvider(FakeProvider):
        def __init__(self):
            super().__init__()
            self.room_calls = []

        def create_room(self, prime_prompt=None):
            self.room_calls.append(prime_prompt)
            return 'summary-room'

    _mock_company_ai_cache(monkeypatch, [cached_item])
    providers = []

    def factory(config):
        provider = TrackingProvider()
        providers.append(provider)
        return provider

    monkeypatch.setattr('report_harness.CompanyAIProvider', factory)
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job_id = create_job( [sample_document()], 'test', 'company_ai')
            run_job(app, job_id)
            job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'completed'
            assert providers == []
            assert 'company_ai_conversation_id' not in job
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root
            get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id)})


def test_company_ai_cache_miss_uses_template(tmp_path, monkeypatch):
    _mock_company_ai_cache(monkeypatch, [None])
    monkeypatch.setattr('report_harness.CompanyAIProvider', lambda config: FakeProvider())
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job_id = create_job( [sample_document()], 'test', 'company_ai')
            run_job(app, job_id)
            job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'completed'
            assert job['item_fallback_count'] == 1
            assert job['report']['highlights'][0]['title'] == 'Vulnerability 1'
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root
            get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id)})


def test_company_ai_report_job_falls_back_to_template(tmp_path, monkeypatch):
    class FailingProvider:
        max_output = 500

        def create_room(self, prime_prompt=None):
            return 'room'

        def delete_room(self):
            return None

        def complete_json(self, system_prompt, user_prompt):
            raise ProviderError('Company AI unavailable.')

    _mock_company_ai_cache(monkeypatch, [None])
    monkeypatch.setattr('report_harness.CompanyAIProvider', lambda config: FailingProvider())
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job_id = create_job( [sample_document()], 'test', 'company_ai', 'zh')
            run_job(app, job_id)
            job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'completed'
            assert job['generation_mode'] == 'company_ai'
            assert job['effective_generation_mode'] == 'company_ai'
            assert job['report_language'] == 'zh'
            assert job['effective_report_language'] == 'zh'
            assert job['item_fallback_count'] == 1
            assert 'Timed out waiting for the prioritized Company AI summary.' in job['item_errors'][0]['error']
            assert 'final_summary_fallback_reason' not in job
            assert 'usage' not in job
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root
            get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id)})


def test_company_ai_authentication_failure_uses_template_and_deterministic_final(tmp_path, monkeypatch):
    class AuthenticationFailure:
        def create_room(self, prime_prompt=None):
            raise ProviderError('Company AI login failed.')

        def delete_room(self):
            return None

    _mock_company_ai_cache(monkeypatch, [None])
    monkeypatch.setattr('report_harness.CompanyAIProvider', lambda config: AuthenticationFailure())
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job_id = create_job( [sample_document()], 'test', 'company_ai')
            run_job(app, job_id)
            job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'completed'
            assert 'room_creation_warning' not in job
            assert job['item_fallback_count'] == 1
            assert 'final_summary_fallback_reason' not in job
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root
            get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id)})


def test_queued_final_timeout_uses_deterministic_final(tmp_path, monkeypatch):
    class FinalFailureProvider(FakeProvider):
        def create_room(self, prime_prompt=None):
            return 'room'

        def delete_room(self):
            return None

        def complete_json(self, system_prompt, user_prompt):
            if not user_prompt.startswith('Review details:'):
                raise ProviderError('Company AI final unavailable.')
            return super().complete_json(system_prompt, user_prompt)

    cached_item = {
        'highlight': {'title': 'Cached', 'summary': 'Summary'},
        'recommendations': [],
    }
    _mock_company_ai_cache(monkeypatch, [cached_item])
    monkeypatch.setattr(
        'company_ai_preprocessor.wait_for_summaries',
        lambda references, timeout, should_continue=None: [None] if references[0].get('task_type') == 'final'
        else [cached_item],
    )
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job_id = create_job( [sample_document()], 'test', 'company_ai')
            run_job(app, job_id)
            job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'completed'
            assert job['item_fallback_count'] == 0
            assert job['final_summary_fallback_reason'] == (
                'Timed out waiting for the queued final AI summary.'
            )
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root
            get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id)})


def test_company_ai_template_fallback_leaves_preprocess_cache_pending(tmp_path, monkeypatch):
    _mock_company_ai_cache(monkeypatch, [None])
    monkeypatch.setattr('report_harness.CompanyAIProvider', lambda config: FakeProvider())
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        upload_collection = get_web_database()['company_ai_upload_summaries']
        upload_collection.delete_many({})
        upload_collection.insert_one({
            '_id': ObjectId(),
            'source_key': 'upload:test',
            'language': 'en',
            'content_hash': 'hash-0',
            'status': 'pending',
        })
        try:
            job_id = create_job( [sample_document()], 'test', 'company_ai')
            run_job(app, job_id)
            job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            entry = upload_collection.find_one({'content_hash': 'hash-0'})
            assert job['item_fallback_count'] == 1
            assert entry['status'] == 'pending'
            assert 'result' not in entry
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root
            upload_collection.delete_many({})
            get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id)})


def test_company_ai_schema_failure_falls_back_to_template(tmp_path, monkeypatch):
    class InvalidProvider:
        max_output = 500

        def create_room(self, prime_prompt=None):
            return 'room'

        def delete_room(self):
            return None

        def complete_json(self, system_prompt, user_prompt):
            return {'unexpected': True}, {}

    _mock_company_ai_cache(monkeypatch, [None])
    monkeypatch.setattr('report_harness.CompanyAIProvider', lambda config: InvalidProvider())
    with app.app_context():
        original_root = app.config['NEWSLETTER_ROOT']
        app.config['NEWSLETTER_ROOT'] = str(tmp_path)
        try:
            job_id = create_job( [sample_document()], 'test', 'company_ai')
            run_job(app, job_id)
            job = get_web_database()['report_jobs'].find_one({'_id': ObjectId(job_id)})
            assert job['status'] == 'completed'
            assert job['effective_generation_mode'] == 'company_ai'
            assert job['item_fallback_count'] == 1
            assert 'Timed out waiting for the prioritized Company AI summary.' in job['item_errors'][0]['error']
            assert 'final_summary_fallback_reason' not in job
        finally:
            app.config['NEWSLETTER_ROOT'] = original_root
            get_web_database()['report_jobs'].delete_one({'_id': ObjectId(job_id)})

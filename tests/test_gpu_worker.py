import json

from GPU_server.gpu_worker import (
    LocalGPUProvider,
    compact_details,
    process_task,
    summary_content_hash,
)
from company_ai_preprocessor import summary_content_hash as application_summary_content_hash


def _config():
    return {
        'GPU_INFERENCE_BASE_URL': 'http://llama-server:8080/v1',
        'GPU_MODEL_NAME': 'qwen-local',
        'GPU_REQUEST_TIMEOUT_SECONDS': 10,
        'GPU_JSON_RETRIES': 0,
        'GPU_MAX_OUTPUT_TOKENS': 1000,
        'GPU_START_PROMPT': 'Prime this chat for vulnerability JSON.',
        'GPU_ENABLED': True,
        'COMPANY_AI_ENABLED': True,
        'PREPROCESSING_CACHE_VERSION': '1',
        'REPORT_DENY_KEYS': ['raw'],
        'REPORT_DENY_PREFIXES': ['raw_'],
        'REPORT_MAX_DEPTH': 6,
        'REPORT_MAX_LIST_ITEMS': 100,
        'REPORT_MAX_STRING_CHARS': 12000,
    }


def test_gpu_worker_hash_matches_application_hash():
    config = _config()
    details = compact_details(
        {'source': {'description': 'evidence', 'raw_data': 'remove'}},
        config,
    )
    assert summary_content_hash(details, 'en', config) == application_summary_content_hash(
        details,
        'en',
        config,
    )


def test_local_gpu_provider_requests_schema_constrained_json(monkeypatch):
    requests = []
    result = {
        'highlight': {'summary': 'Evidence-based summary.'},
        'recommendations': ['Patch the affected system.'],
    }

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {'choices': [{'message': {'content': json.dumps(result)}}]}

    def fake_post(url, json, timeout):
        requests.append((url, json, timeout))
        return FakeResponse()

    monkeypatch.setattr('GPU_server.gpu_worker.requests.post', fake_post)
    provider = LocalGPUProvider(_config())
    provider.open_chat()
    generated = provider.generate_item({'description': 'evidence'}, 'English')
    provider.close_chat()
    assert generated == result
    assert requests[0][0].endswith('/chat/completions')
    assert 'response_format' not in requests[0][1]
    assert requests[1][1]['response_format']['type'] == 'json_schema'
    assert requests[1][1]['messages'][0]['content'] == _config()['GPU_START_PROMPT']
    assert provider.messages is None


def test_local_gpu_provider_corrects_invalid_json_in_same_chat(monkeypatch):
    responses = [
        'primed',
        'not json',
        json.dumps({
            'highlight': {'summary': 'Corrected summary.'},
            'recommendations': [],
        }),
    ]
    payloads = []

    class FakeResponse:
        def __init__(self, content):
            self.content = content

        def raise_for_status(self):
            return None

        def json(self):
            return {'choices': [{'message': {'content': self.content}}]}

    def fake_post(url, json, timeout):
        payloads.append({
            **json,
            'messages': [dict(message) for message in json['messages']],
        })
        return FakeResponse(responses.pop(0))

    monkeypatch.setattr('GPU_server.gpu_worker.requests.post', fake_post)
    config = {**_config(), 'GPU_JSON_RETRIES': 1}
    provider = LocalGPUProvider(config)
    provider.open_chat()
    result = provider.generate_item({'description': 'evidence'}, 'English')
    provider.close_chat()
    assert result['highlight']['summary'] == 'Corrected summary.'
    correction_messages = payloads[2]['messages']
    assert correction_messages[-2] == {'role': 'assistant', 'content': 'not json'}
    assert 'previous response was invalid' in correction_messages[-1]['content']


def test_gpu_failure_resets_task_and_routes_to_company(monkeypatch):
    updates = []
    published = []
    config = {
        **_config(),
        'RABBITMQ_COMPANY_QUEUE': 'company',
        'RABBITMQ_GPU_QUEUE': 'gpu',
        'RABBITMQ_BACKGROUND_PRIORITY': 1,
        'GPU_MAX_TASK_ATTEMPTS': 2,
    }

    class FakeCollection:
        def find_one(self, *args, **kwargs):
            return {'details': {'description': 'evidence'}}

    class FakeDatabase:
        def __getitem__(self, name):
            return FakeCollection()

    class FailingProvider:
        def open_chat(self):
            return None

        def close_chat(self):
            return None

        def generate_item(self, details, language):
            raise RuntimeError('GPU unavailable')

    monkeypatch.setattr(
        'GPU_server.gpu_worker.claim_task',
        lambda collection, task, owner, config: {'attempts': 2},
    )
    monkeypatch.setattr(
        'GPU_server.gpu_worker.update_task',
        lambda collection, task, owner, values, unset: updates.append(values),
    )
    monkeypatch.setattr(
        'GPU_server.gpu_worker.publish',
        lambda channel, queue, task, priority, config: published.append(queue),
    )
    task = {
        'storage': 'source',
        'source_collection': 'source',
        'source_id': 'item',
        'language': 'en',
        'content_hash': summary_content_hash({'description': 'evidence'}, 'en', config),
    }
    process_task(FakeDatabase(), object(), task, 'gpu-owner', FailingProvider(), config)
    assert updates[-1]['status'] == 'pending'
    assert updates[-1]['error'] == 'GPU unavailable'
    assert published == ['company']

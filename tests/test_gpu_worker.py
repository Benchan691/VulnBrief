import json

from GPU_server.gpu_worker import (
    LocalGPUProvider,
    compact_details,
    declare_queues,
    inference_base_url_for_worker,
    load_config,
    load_inference_base_urls,
    process_task,
    publish,
    summary_content_hash,
    wait_for_queue_capacity,
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
        'GPU_FINAL_SUMMARY_PROMPT': 'Summarize in ${language}.',
        'AI_TASK_COLLECTION': 'ai_generation_tasks',
        'GPU_ENABLED': True,
        'COMPANY_AI_ENABLED': True,
        'RABBITMQ_MAX_PRIORITY': 10,
        'RABBITMQ_MAX_QUEUE_SIZE': 19999,
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


def test_gpu_queue_declarations_include_max_length():
    declarations = []

    class FakeChannel:
        def queue_declare(self, **kwargs):
            declarations.append(kwargs)
            return type('Status', (), {'method': type('Method', (), {'message_count': 0})()})()

    config = {
        **_config(),
        'RABBITMQ_COMPANY_QUEUE': 'company',
        'RABBITMQ_GPU_QUEUE': 'gpu',
    }
    declare_queues(FakeChannel(), config)
    assert declarations == [
        {
            'queue': 'company',
            'durable': True,
            'arguments': {'x-max-priority': 10, 'x-max-length': 19999},
        },
        {
            'queue': 'gpu',
            'durable': True,
            'arguments': {'x-max-priority': 10, 'x-max-length': 19999},
        },
    ]


def test_gpu_publish_waits_for_queue_capacity(monkeypatch):
    waits = []
    published = []
    counts = [19999, 19998]

    class FakeChannel:
        def queue_declare(self, **kwargs):
            return type(
                'Status',
                (),
                {'method': type('Method', (), {'message_count': counts.pop(0)})()},
            )()

        def basic_publish(self, **kwargs):
            published.append(kwargs)

    monkeypatch.setattr(
        'GPU_server.gpu_worker.STOP_EVENT.wait',
        lambda seconds: waits.append(seconds) and False,
    )
    config = {
        **_config(),
        'RABBITMQ_COMPANY_QUEUE': 'company',
        'RABBITMQ_GPU_QUEUE': 'gpu',
    }
    assert wait_for_queue_capacity(FakeChannel(), 'company', config) is True
    assert waits == [1]

    counts[:] = [19998]
    assert publish(FakeChannel(), 'company', {'storage': 'source'}, 1, config) is True
    assert published


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
    process_task(FakeDatabase(), object(), task, 'gpu-owner', FailingProvider(), config, 0)
    assert updates[-1]['status'] == 'pending'
    assert updates[-1]['error'] == 'GPU unavailable'
    assert published == ['company']


def test_gpu_processes_shared_final_task(monkeypatch):
    updates = []
    payload = {'item_results': [{'highlight': {'summary': 'Item'}, 'recommendations': []}]}
    config = {
        **_config(),
        'RABBITMQ_COMPANY_QUEUE': 'company',
        'RABBITMQ_GPU_QUEUE': 'gpu',
        'RABBITMQ_BACKGROUND_PRIORITY': 1,
        'GPU_MAX_TASK_ATTEMPTS': 2,
    }

    class FakeCollection:
        pass

    class FakeDatabase:
        def __getitem__(self, name):
            return FakeCollection()

    class Provider:
        def open_chat(self):
            return None

        def close_chat(self):
            return None

        def generate_final(self, item_results, language, prompt):
            assert item_results == payload['item_results']
            return {'executive_summary': 'GPU final', 'trends': [], 'recommendations': []}

    monkeypatch.setattr(
        'GPU_server.gpu_worker.claim_shared_task',
        lambda collection, task, owner, config: {'attempts': 1, 'payload': payload},
    )
    monkeypatch.setattr(
        'GPU_server.gpu_worker.update_shared_task',
        lambda collection, task, owner, values, unset: updates.append(values),
    )
    task = {
        'storage': 'shared',
        'task_id': 'task',
        'task_type': 'final',
        'language': 'en',
        'content_hash': summary_content_hash(payload, 'en', config),
    }
    process_task(FakeDatabase(), object(), task, 'gpu-owner', Provider(), config, 0)
    assert updates[-1]['status'] == 'completed'
    assert updates[-1]['provider'] == 'gpu_local'
    assert updates[-1]['result']['executive_summary'] == 'GPU final'


def test_load_inference_base_urls_from_instance_count(monkeypatch):
    monkeypatch.delenv('GPU_INFERENCE_BASE_URLS', raising=False)
    monkeypatch.setenv('GPU_INSTANCE_COUNT', '3')
    monkeypatch.delenv('GPU_INFERENCE_BASE_URL', raising=False)

    assert load_inference_base_urls() == [
        'http://llama-server-0:8080/v1',
        'http://llama-server-1:8080/v1',
        'http://llama-server-2:8080/v1',
    ]


def test_load_inference_base_urls_explicit_list(monkeypatch):
    monkeypatch.setenv(
        'GPU_INFERENCE_BASE_URLS',
        'http://a:8080/v1, http://b:8080/v1',
    )

    assert load_inference_base_urls() == ['http://a:8080/v1', 'http://b:8080/v1']


def test_load_config_defaults_worker_concurrency_to_instance_count(monkeypatch):
    monkeypatch.setenv('ATLAS_MONGO_URI', 'mongodb://localhost:27017')
    monkeypatch.setenv('RABBITMQ_URL', 'amqp://guest:guest@localhost:5672')
    monkeypatch.setenv('GPU_INSTANCE_COUNT', '3')
    monkeypatch.delenv('GPU_WORKER_CONCURRENCY', raising=False)
    monkeypatch.delenv('GPU_INFERENCE_BASE_URLS', raising=False)

    config = load_config()

    assert config['GPU_INSTANCE_COUNT'] == 3
    assert config['GPU_WORKER_CONCURRENCY'] == 3
    assert inference_base_url_for_worker(config, 0) == 'http://llama-server-0:8080/v1'
    assert inference_base_url_for_worker(config, 2) == 'http://llama-server-2:8080/v1'
    assert inference_base_url_for_worker(config, 3) == 'http://llama-server-0:8080/v1'


def test_local_gpu_provider_uses_worker_specific_base_url():
    config = _config()
    provider = LocalGPUProvider(config, base_url='http://llama-server-1:8080/v1')
    assert provider.base_url == 'http://llama-server-1:8080/v1'

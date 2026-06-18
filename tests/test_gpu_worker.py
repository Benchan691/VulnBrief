import json
import os

import pytest
import requests

from GPU_server import gpu_worker
from GPU_server.gpu_config import load_gpu_server_config
from GPU_server.gpu_worker import (
    LocalGPUProvider,
    _build_llama_server_command,
    _inference_urls_are_localhost,
    _resolve_model_path,
    compact_details,
    declare_queues,
    inference_base_url_for_worker,
    load_config,
    load_inference_base_urls,
    process_task,
    probe_inference_urls,
    publish,
    start_llama_servers,
    stop_llama_servers,
    summary_content_hash,
    wait_for_inference_urls,
    wait_for_queue_capacity,
    _inference_health_url,
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


def test_load_inference_base_urls_from_instance_count_docker(monkeypatch):
    monkeypatch.delenv('GPU_INFERENCE_BASE_URLS', raising=False)
    monkeypatch.setenv('GPU_INSTANCE_COUNT', '3')
    monkeypatch.delenv('GPU_INFERENCE_BASE_URL', raising=False)
    monkeypatch.delenv('GPU_INFERENCE_HOST', raising=False)
    monkeypatch.setenv('GPU_INFERENCE_NETWORK', 'docker')

    assert load_inference_base_urls() == [
        'http://llama-server-0:8080/v1',
        'http://llama-server-1:8080/v1',
        'http://llama-server-2:8080/v1',
    ]


def test_load_inference_base_urls_from_instance_count_host(monkeypatch):
    monkeypatch.delenv('GPU_INFERENCE_BASE_URLS', raising=False)
    monkeypatch.setenv('GPU_INSTANCE_COUNT', '3')
    monkeypatch.delenv('GPU_INFERENCE_BASE_URL', raising=False)
    monkeypatch.delenv('GPU_INFERENCE_HOST', raising=False)
    monkeypatch.delenv('GPU_INFERENCE_NETWORK', raising=False)

    assert load_inference_base_urls() == [
        'http://127.0.0.1:8080/v1',
        'http://127.0.0.1:8081/v1',
        'http://127.0.0.1:8082/v1',
    ]


def test_load_inference_base_urls_host_override(monkeypatch):
    monkeypatch.delenv('GPU_INFERENCE_BASE_URLS', raising=False)
    monkeypatch.setenv('GPU_INSTANCE_COUNT', '2')
    monkeypatch.setenv('GPU_INFERENCE_HOST', '10.0.0.5')
    monkeypatch.setenv('GPU_INFERENCE_BASE_PORT', '9000')

    assert load_inference_base_urls() == [
        'http://10.0.0.5:9000/v1',
        'http://10.0.0.5:9001/v1',
    ]


def test_load_inference_base_urls_explicit_list(monkeypatch):
    monkeypatch.setenv(
        'GPU_INFERENCE_BASE_URLS',
        'http://a:8080/v1, http://b:8080/v1',
    )

    assert load_inference_base_urls() == ['http://a:8080/v1', 'http://b:8080/v1']


def test_inference_health_url():
    assert _inference_health_url('http://127.0.0.1:8081/v1') == 'http://127.0.0.1:8081/health'


def test_probe_inference_urls_reports_unreachable(monkeypatch):
    class FakeResponse:
        status_code = 200

    def fake_get(url, timeout):
        if url.endswith(':8081/health'):
            raise requests.exceptions.ConnectionError('connection refused')
        return FakeResponse()

    monkeypatch.setattr('GPU_server.gpu_worker.requests.get', fake_get)

    issues = probe_inference_urls([
        'http://127.0.0.1:8080/v1',
        'http://127.0.0.1:8081/v1',
    ])

    assert len(issues) == 1
    assert issues[0]['worker'] == 1
    assert issues[0]['health_url'] == 'http://127.0.0.1:8081/health'


def test_wait_for_inference_urls_retries_until_ready(monkeypatch):
    attempts = {'count': 0}

    def fake_probe(urls, timeout_seconds=3):
        attempts['count'] += 1
        if attempts['count'] < 3:
            return [{
                'worker': 0,
                'url': urls[0],
                'health_url': 'http://127.0.0.1:8080/health',
                'error': 'HTTP 502',
                'status_code': 502,
                'body_preview': '',
            }]
        return []

    monkeypatch.setattr('GPU_server.gpu_worker.probe_inference_urls', fake_probe)

    class FakeStopEvent:
        def wait(self, timeout):
            return False

    monkeypatch.setattr('GPU_server.gpu_worker.STOP_EVENT', FakeStopEvent())

    issues = wait_for_inference_urls(['http://127.0.0.1:8080/v1'], wait_seconds=30, poll_seconds=1)

    assert issues == []
    assert attempts['count'] == 3


def test_load_gpu_server_config_reads_json(tmp_path, monkeypatch):
    monkeypatch.setenv('ATLAS_MONGO_URI', 'mongodb://localhost:27017')
    monkeypatch.setenv('RABBITMQ_URL', 'amqp://guest:guest@localhost:5672')
    monkeypatch.delenv('GPU_MODEL_PATH', raising=False)
    monkeypatch.delenv('RABBITMQ_GPU_QUEUE', raising=False)
    monkeypatch.delenv('GPU_INFERENCE_BASE_URL', raising=False)
    config_path = tmp_path / 'gpu_server.json'
    config_path.write_text(
        json.dumps({
            'inference': {
                'instance_count': 1,
                'worker_concurrency': 1,
                'model_path': '/models/custom.gguf',
                'docker_base_url': 'http://host.docker.internal:8080/v1',
            },
            'rabbitmq': {'gpu_queue': 'gpu_test'},
            'mongodb': {},
            'processing': {},
            'prompts': {},
            'report_compaction': {},
            'flags': {},
        }),
        encoding='utf-8',
    )
    monkeypatch.setenv('GPU_SERVER_CONFIG', str(config_path))

    config = load_gpu_server_config(
        base_dir=str(tmp_path),
        running_in_docker=lambda: True,
    )

    assert config['GPU_MODEL_PATH'] == '/models/custom.gguf'
    assert config['RABBITMQ_GPU_QUEUE'] == 'gpu_test'
    assert config['GPU_INFERENCE_BASE_URLS'] == ['http://host.docker.internal:8080/v1']


def test_load_config_uses_json_defaults(monkeypatch):
    monkeypatch.setenv('ATLAS_MONGO_URI', 'mongodb://localhost:27017')
    monkeypatch.setenv('RABBITMQ_URL', 'amqp://guest:guest@localhost:5672')
    for key in (
        'GPU_INSTANCE_COUNT',
        'GPU_WORKER_CONCURRENCY',
        'GPU_INFERENCE_BASE_URLS',
        'GPU_INFERENCE_BASE_URL',
        'GPU_INFERENCE_NETWORK',
        'RABBITMQ_GPU_QUEUE',
        'GPU_MODEL_PATH',
        'GPU_TENSOR_SPLIT',
    ):
        monkeypatch.delenv(key, raising=False)
    gpu_server_dir = os.path.join(os.path.dirname(__file__), '..', 'GPU_server')
    monkeypatch.setenv(
        'GPU_SERVER_CONFIG',
        os.path.join(gpu_server_dir, 'config', 'gpu_server.json'),
    )

    config = load_config()

    assert config['GPU_INSTANCE_COUNT'] == 1
    assert config['GPU_WORKER_CONCURRENCY'] == 1
    assert config['GPU_TENSOR_SPLIT'] == '1,1,1'
    assert config['RABBITMQ_GPU_QUEUE'] == 'gpu_processing'
    assert config['GPU_MODEL_PATH'] == '/models/Qwen3_Qwen3_30B-A3B-Instruct-2507_Q4_K_M.gguf'
    assert config['GPU_INFERENCE_BASE_URLS'] == ['http://127.0.0.1:8080/v1']
    assert inference_base_url_for_worker(config, 0) == 'http://127.0.0.1:8080/v1'


def test_load_inference_base_urls_single_instance_docker(monkeypatch):
    monkeypatch.delenv('GPU_INFERENCE_BASE_URLS', raising=False)
    monkeypatch.delenv('GPU_INFERENCE_BASE_URL', raising=False)
    monkeypatch.setenv('GPU_INSTANCE_COUNT', '1')
    monkeypatch.setenv('GPU_INFERENCE_NETWORK', 'docker')

    assert load_inference_base_urls() == ['http://host.docker.internal:8080/v1']


def _llama_config():
    return {
        **_config(),
        'GPU_INSTANCE_COUNT': 3,
        'GPU_INFERENCE_BASE_URLS': [
            'http://127.0.0.1:8080/v1',
            'http://127.0.0.1:8081/v1',
            'http://127.0.0.1:8082/v1',
        ],
        'GPU_MODEL_PATH': '/models/test-model.gguf',
        'GPU_CONTEXT_SIZE': 4096,
        'GPU_TENSOR_SPLIT': '1,1,1',
        'GPU_LLAMA_LOG_VERBOSITY': 1,
        'GPU_AUTO_START_LLAMA_SERVERS': True,
    }


def test_resolve_model_path_maps_docker_style_path(tmp_path, monkeypatch):
    models_dir = tmp_path / 'models'
    models_dir.mkdir()
    model_file = models_dir / 'test-model.gguf'
    model_file.write_text('gguf', encoding='utf-8')
    monkeypatch.setattr(gpu_worker, '_gpu_server_dir', lambda: str(tmp_path))

    assert _resolve_model_path('/models/test-model.gguf') == str(model_file)


def test_resolve_model_path_accepts_absolute_host_path(tmp_path):
    model_file = tmp_path / 'custom-model.gguf'
    model_file.write_text('gguf', encoding='utf-8')

    assert _resolve_model_path(str(model_file)) == str(model_file)


def test_inference_urls_are_localhost():
    assert _inference_urls_are_localhost(['http://127.0.0.1:8080/v1']) is True
    assert _inference_urls_are_localhost(['http://llama-server-0:8080/v1']) is False


def test_build_llama_server_command_per_gpu_ports_and_devices(tmp_path, monkeypatch):
    models_dir = tmp_path / 'models'
    models_dir.mkdir()
    (models_dir / 'test-model.gguf').write_text('gguf', encoding='utf-8')
    monkeypatch.setattr(gpu_worker, '_gpu_server_dir', lambda: str(tmp_path))
    monkeypatch.setenv('GPU_LLAMA_SERVER_BIN', str(tmp_path / 'llama-server'))
    (tmp_path / 'llama-server').write_text('', encoding='utf-8')

    config = _llama_config()
    for index, port, gpu in ((0, '8080', '0'), (1, '8081', '1'), (2, '8082', '2')):
        cmd, env = _build_llama_server_command(config, index)
        assert cmd[cmd.index('--port') + 1] == port
        assert env['CUDA_VISIBLE_DEVICES'] == gpu
        assert '--tensor-split' not in cmd


def test_build_llama_server_command_tensor_split_mode(tmp_path, monkeypatch):
    models_dir = tmp_path / 'models'
    models_dir.mkdir()
    (models_dir / 'test-model.gguf').write_text('gguf', encoding='utf-8')
    monkeypatch.setattr(gpu_worker, '_gpu_server_dir', lambda: str(tmp_path))
    monkeypatch.setenv('GPU_LLAMA_SERVER_BIN', str(tmp_path / 'llama-server'))
    (tmp_path / 'llama-server').write_text('', encoding='utf-8')

    config = {
        **_llama_config(),
        'GPU_INSTANCE_COUNT': 1,
        'GPU_INFERENCE_BASE_URLS': ['http://127.0.0.1:8080/v1'],
        'GPU_TENSOR_SPLIT': '1,1,1',
    }
    cmd, env = _build_llama_server_command(config, 0)
    assert cmd[cmd.index('--tensor-split') + 1] == '1,1,1'
    assert 'CUDA_VISIBLE_DEVICES' not in env


def test_start_llama_servers_skips_when_healthy(monkeypatch):
    monkeypatch.setattr(
        'GPU_server.gpu_worker.probe_inference_urls',
        lambda urls, timeout_seconds=3: [],
    )
    monkeypatch.setattr(
        'GPU_server.gpu_worker.subprocess.Popen',
        lambda *args, **kwargs: pytest.fail('Popen should not be called'),
    )

    start_llama_servers(_llama_config())


def test_start_llama_servers_spawns_missing_instances(tmp_path, monkeypatch):
    models_dir = tmp_path / 'models'
    models_dir.mkdir()
    (models_dir / 'test-model.gguf').write_text('gguf', encoding='utf-8')
    monkeypatch.setattr(gpu_worker, '_gpu_server_dir', lambda: str(tmp_path))
    monkeypatch.setenv('GPU_LLAMA_SERVER_BIN', str(tmp_path / 'llama-server'))
    (tmp_path / 'llama-server').write_text('', encoding='utf-8')
    monkeypatch.setattr(
        'GPU_server.gpu_worker.probe_inference_urls',
        lambda urls, timeout_seconds=3: [
            {'worker': 0, 'url': urls[0], 'health_url': 'http://127.0.0.1:8080/health', 'error': 'refused'},
            {'worker': 2, 'url': urls[2], 'health_url': 'http://127.0.0.1:8082/health', 'error': 'refused'},
        ],
    )

    launched = []

    class FakeProcess:
        pid = 1234

        def poll(self):
            return None

        def terminate(self):
            return None

        def wait(self, timeout=None):
            return 0

        def kill(self):
            return None

    def fake_popen(cmd, env, cwd):
        launched.append((cmd, env, cwd))
        return FakeProcess()

    monkeypatch.setattr('GPU_server.gpu_worker.subprocess.Popen', fake_popen)
    gpu_worker.LLAMA_SERVER_PROCESSES = []

    start_llama_servers(_llama_config())

    assert len(launched) == 2
    assert launched[0][0][launched[0][0].index('--port') + 1] == '8080'
    assert launched[0][1]['CUDA_VISIBLE_DEVICES'] == '0'
    assert launched[1][0][launched[1][0].index('--port') + 1] == '8082'
    assert launched[1][1]['CUDA_VISIBLE_DEVICES'] == '2'


def test_stop_llama_servers_terminates_tracked_processes(monkeypatch):
    terminated = []

    class FakeProcess:
        def poll(self):
            return None

        def terminate(self):
            terminated.append('terminate')

        def wait(self, timeout=None):
            return 0

        def kill(self):
            terminated.append('kill')

    gpu_worker.LLAMA_SERVER_PROCESSES = [FakeProcess(), FakeProcess()]
    stop_llama_servers()

    assert terminated == ['terminate', 'terminate']
    assert gpu_worker.LLAMA_SERVER_PROCESSES == []


def test_local_gpu_provider_uses_worker_specific_base_url():
    config = _config()
    provider = LocalGPUProvider(config, base_url='http://llama-server-1:8080/v1')
    assert provider.base_url == 'http://llama-server-1:8080/v1'

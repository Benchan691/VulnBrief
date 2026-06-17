import atexit
import hashlib
import html
import json
import os
import shutil
import signal
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import pika
import requests
from bson import json_util
from dotenv import load_dotenv
try:
    from gpu_config import load_gpu_server_config, resolve_inference_base_urls
except ImportError:
    from GPU_server.gpu_config import load_gpu_server_config, resolve_inference_base_urls
from jsonschema import ValidationError, validate
from pymongo import MongoClient, ReturnDocument

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

STOP_EVENT = threading.Event()
LLAMA_SERVER_PROCESSES = []
QUEUE_CAPACITY_WAIT_SECONDS = 1
REPORT_LANGUAGES = {
    'en': 'English',
    'zh': 'Traditional Chinese',
    'ch': 'Simplified Chinese',
}


def _format_log_fields(fields):
    if not fields:
        return ''
    return ' ' + ' '.join(f'{key}={value}' for key, value in fields.items())


def log_info(message, **fields):
    print(f'[preprocessor] {message}{_format_log_fields(fields)}', flush=True)


def log_error(message, **fields):
    print(f'[preprocessor] ERROR {message}{_format_log_fields(fields)}', flush=True)


def _preview_text(text, limit):
    normalized = ' '.join((text or '').split())
    if len(normalized) <= limit:
        return normalized
    return normalized[:limit] + '...'


def _preview_bytes(body, limit):
    if isinstance(body, bytes):
        body = body.decode('utf-8', errors='replace')
    return _preview_text(body, limit)


def log_llm_message(config, direction, role, content, **fields):
    if not config.get('GPU_LOG_MESSAGES'):
        return
    log_info(
        'LLM message',
        direction=direction,
        role=role,
        content=_preview_text(content, config['GPU_LOG_MESSAGE_CHARS']),
        **fields,
    )


def _running_in_docker():
    if os.environ.get('GPU_INFERENCE_NETWORK', '').strip().lower() == 'docker':
        return True
    return os.path.exists('/.dockerenv')


def _hostname_resolves(hostname):
    if not hostname:
        return False
    if hostname in {'127.0.0.1', 'localhost', '::1'}:
        return True
    try:
        socket.getaddrinfo(hostname, None)
        return True
    except socket.gaierror:
        return False


def validate_inference_urls(urls):
    issues = []
    for index, url in enumerate(urls):
        hostname = urlparse(url).hostname or ''
        if not _hostname_resolves(hostname):
            issues.append({'worker': index, 'url': url, 'hostname': hostname})
    return issues


def _inference_health_url(base_url):
    trimmed = base_url.rstrip('/')
    if trimmed.endswith('/v1'):
        return trimmed[:-3] + '/health'
    return trimmed + '/health'


def probe_inference_urls(urls, timeout_seconds=3):
    issues = []
    for index, url in enumerate(urls):
        health_url = _inference_health_url(url)
        try:
            response = requests.get(health_url, timeout=timeout_seconds)
            if response.status_code >= 400:
                issues.append({
                    'worker': index,
                    'url': url,
                    'health_url': health_url,
                    'error': f'HTTP {response.status_code}',
                    'status_code': response.status_code,
                    'body_preview': (response.text or '')[:200],
                })
        except requests.RequestException as exc:
            issues.append({
                'worker': index,
                'url': url,
                'health_url': health_url,
                'error': str(exc),
                'status_code': None,
                'body_preview': '',
            })
    return issues


def _gpu_server_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _resolve_model_path(model_path):
    if not model_path:
        raise ValueError('GPU_MODEL_PATH must be configured for llama-server auto-start.')
    if model_path.startswith('/models/'):
        local_path = os.path.join(
            _gpu_server_dir(),
            'models',
            os.path.basename(model_path),
        )
        if os.path.isfile(local_path):
            return local_path
    if os.path.isfile(model_path):
        return os.path.abspath(model_path)
    raise ValueError(f'Model file not found: {model_path}')


def _inference_urls_are_localhost(urls):
    for url in urls:
        hostname = (urlparse(url).hostname or '').casefold()
        if hostname not in {'127.0.0.1', 'localhost', '::1'}:
            return False
    return bool(urls)


def _inference_url_port(url):
    parsed = urlparse(url)
    if parsed.port is not None:
        return parsed.port
    return 8080


def _llama_server_binary():
    configured = os.environ.get('GPU_LLAMA_SERVER_BIN', '').strip()
    if configured:
        return configured if os.path.isfile(configured) else None
    return shutil.which('llama-server')


def _build_llama_server_command(config, index):
    binary = _llama_server_binary()
    if not binary:
        raise ValueError(
            'llama-server binary not found; set GPU_LLAMA_SERVER_BIN or add llama-server to PATH.',
        )
    model_path = _resolve_model_path(config['GPU_MODEL_PATH'])
    port = _inference_url_port(config['GPU_INFERENCE_BASE_URLS'][index])
    env = os.environ.copy()
    cmd = [
        binary,
        '-m',
        model_path,
        '--host',
        '127.0.0.1',
        '--port',
        str(port),
        '-ngl',
        '99',
        '-c',
        str(config['GPU_CONTEXT_SIZE']),
        '--parallel',
        '1',
        '--log-verbosity',
        str(config['GPU_LLAMA_LOG_VERBOSITY']),
    ]
    if config['GPU_INSTANCE_COUNT'] <= 1:
        tensor_split = config['GPU_TENSOR_SPLIT']
        if tensor_split:
            cmd.extend(['--tensor-split', tensor_split])
    else:
        env['CUDA_VISIBLE_DEVICES'] = str(index)
    return cmd, env


def _should_auto_start_llama_servers(config, inference_urls):
    if _running_in_docker():
        return False
    if not config['GPU_AUTO_START_LLAMA_SERVERS']:
        return False
    if not _inference_urls_are_localhost(inference_urls):
        return False
    return bool(probe_inference_urls(inference_urls))


def start_llama_servers(config):
    urls = config['GPU_INFERENCE_BASE_URLS']
    issues = probe_inference_urls(urls)
    if not issues:
        return

    unreachable_indices = sorted({issue['worker'] for issue in issues})
    binary = _llama_server_binary()
    if not binary:
        log_error(
            'Cannot auto-start llama-server; binary not found',
            hint='Set GPU_LLAMA_SERVER_BIN or add llama-server to PATH.',
        )
        raise SystemExit(1)

    try:
        _resolve_model_path(config['GPU_MODEL_PATH'])
    except ValueError as exc:
        log_error('Cannot auto-start llama-server', error=str(exc))
        raise SystemExit(1) from exc

    for index in unreachable_indices:
        cmd, env = _build_llama_server_command(config, index)
        process = subprocess.Popen(cmd, env=env, cwd=_gpu_server_dir())
        LLAMA_SERVER_PROCESSES.append(process)
        log_info(
            'Started llama-server',
            instance=index,
            port=_inference_url_port(urls[index]),
            pid=process.pid,
            gpu=env.get('CUDA_VISIBLE_DEVICES', 'all'),
        )


def stop_llama_servers():
    global LLAMA_SERVER_PROCESSES
    for process in LLAMA_SERVER_PROCESSES:
        if process.poll() is None:
            process.terminate()
    for process in LLAMA_SERVER_PROCESSES:
        if process.poll() is None:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
    LLAMA_SERVER_PROCESSES = []


def wait_for_inference_urls(urls, wait_seconds, poll_seconds=5):
    if wait_seconds <= 0:
        return probe_inference_urls(urls)

    deadline = time.monotonic() + wait_seconds
    attempt = 0
    while True:
        attempt += 1
        issues = probe_inference_urls(urls)
        if not issues:
            if attempt > 1:
                log_info('All inference endpoints ready', attempts=attempt)
            return []

        if time.monotonic() >= deadline:
            return issues

        pending = '; '.join(
            f"worker={issue['worker']} {issue['health_url']} ({issue['error']})"
            for issue in issues
        )
        log_info(
            'Waiting for inference endpoints to become ready',
            attempt=attempt,
            retry_in_seconds=poll_seconds,
            pending=pending,
        )
        if STOP_EVENT.wait(poll_seconds):
            return issues


def _task_target(task):
    if task.get('source_collection') and task.get('source_id') is not None:
        return f"{task['source_collection']}/{task['source_id']}"
    if task.get('task_id') is not None:
        return f"shared/{task['task_id']}"
    return 'unknown'


ITEM_SCHEMA = {
    'type': 'object',
    'required': ['highlight', 'recommendations'],
    'properties': {
        'highlight': {
            'type': 'object',
            'required': ['summary'],
            'properties': {
                'code': {'type': 'string'},
                'severity': {'type': 'string'},
                'summary': {'type': 'string'},
                'affected': {'type': 'array', 'items': {'type': 'string'}},
                'references': {'type': 'array', 'items': {'type': 'string'}},
                'table': {
                    'type': 'object',
                    'required': ['caption', 'headers', 'rows'],
                    'properties': {
                        'caption': {'type': 'string'},
                        'headers': {'type': 'array', 'items': {'type': 'string'}},
                        'rows': {
                            'type': 'array',
                            'items': {'type': 'array', 'items': {'type': 'string'}},
                        },
                    },
                },
            },
        },
        'recommendations': {'type': 'array', 'items': {'type': 'string'}},
    },
}
FINAL_SCHEMA = {
    'type': 'object',
    'required': ['executive_summary', 'trends', 'recommendations'],
    'properties': {
        'executive_summary': {'type': 'string'},
        'trends': {'type': 'array', 'items': {'type': 'string'}},
        'recommendations': {'type': 'array', 'items': {'type': 'string'}},
    },
}


def _inference_settings_from_env():
    instance_count = os.environ.get('GPU_INSTANCE_COUNT')
    return {
        'instance_count': int(instance_count) if instance_count not in (None, '') else 1,
        'base_url': os.environ.get('GPU_INFERENCE_BASE_URL', 'http://llama-server:8080/v1'),
        'docker_base_url': os.environ.get(
            'GPU_INFERENCE_DOCKER_BASE_URL',
            'http://host.docker.internal:8080/v1',
        ),
        'base_port': int(os.environ.get('GPU_INFERENCE_BASE_PORT', 8080)),
        'host': os.environ.get('GPU_INFERENCE_HOST', ''),
    }


def load_inference_base_urls():
    return resolve_inference_base_urls(_inference_settings_from_env(), _running_in_docker)


def inference_base_url_for_worker(config, worker_number):
    urls = config['GPU_INFERENCE_BASE_URLS']
    return urls[worker_number % len(urls)]


def load_config():
    return load_gpu_server_config(_gpu_server_dir(), running_in_docker=_running_in_docker)


def _now():
    return datetime.now(timezone.utc)


def compact_details(details, config):
    deny_keys = {str(key).casefold() for key in config['REPORT_DENY_KEYS']}
    deny_prefixes = tuple(str(prefix).casefold() for prefix in config['REPORT_DENY_PREFIXES'])
    max_depth = config['REPORT_MAX_DEPTH']
    max_list = config['REPORT_MAX_LIST_ITEMS']
    max_string = config['REPORT_MAX_STRING_CHARS']

    def clean(value, depth=0):
        if depth > max_depth:
            return None
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                normalized = str(key).casefold()
                if normalized in deny_keys or normalized.startswith(deny_prefixes):
                    continue
                cleaned = clean(item, depth + 1)
                if cleaned not in (None, '', [], {}):
                    result[str(key)] = cleaned
            return result
        if isinstance(value, (list, tuple, set)):
            result = []
            seen = set()
            for item in list(value)[:max_list]:
                cleaned = clean(item, depth + 1)
                if cleaned in (None, '', [], {}):
                    continue
                marker = json.dumps(cleaned, ensure_ascii=False, sort_keys=True, default=str)
                if marker not in seen:
                    seen.add(marker)
                    result.append(cleaned)
            return result
        if isinstance(value, str):
            return ' '.join(html.unescape(value).split())[:max_string]
        return value

    if not isinstance(details, dict):
        raise ValueError('Source vulnerability details no longer exist.')
    return clean(details)


def summary_content_hash(details, language, config):
    payload = json.dumps(
        {
            'details': details,
            'language': language,
            'cache_version': config['PREPROCESSING_CACHE_VERSION'],
        },
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _language_path(language, field=None):
    path = f'html_json.{language}'
    return f'{path}.{field}' if field else path


def queue_arguments(config):
    return {
        'x-max-priority': config['RABBITMQ_MAX_PRIORITY'],
        'x-max-length': config['RABBITMQ_MAX_QUEUE_SIZE'],
    }


def declare_queues(channel, config):
    channel.queue_declare(
        queue=config['RABBITMQ_COMPANY_QUEUE'],
        durable=True,
        arguments=queue_arguments(config),
    )
    return channel.queue_declare(
        queue=config['RABBITMQ_GPU_QUEUE'],
        durable=True,
        arguments=queue_arguments(config),
    )


def clear_gpu_queue(config):
    connection = pika.BlockingConnection(pika.URLParameters(config['RABBITMQ_URL']))
    try:
        channel = connection.channel()
        declare_queues(channel, config)
        channel.queue_purge(queue=config['RABBITMQ_GPU_QUEUE'])
    finally:
        connection.close()


def try_clear_gpu_queue(config):
    try:
        clear_gpu_queue(config)
        return True
    except pika.exceptions.AMQPError as exc:
        log_error('Unable to clear GPU preprocessing queue', error=str(exc))
        return False


def queue_message_count(channel, queue_name):
    status = channel.queue_declare(queue=queue_name, passive=True)
    return status.method.message_count


def wait_for_queue_capacity(channel, queue_name, config):
    max_size = config['RABBITMQ_MAX_QUEUE_SIZE']
    logged = False
    while queue_message_count(channel, queue_name) >= max_size:
        if not logged:
            log_info(
                'Queue at max size; waiting before publish',
                queue=queue_name,
                max_size=max_size,
            )
            logged = True
        if STOP_EVENT.wait(QUEUE_CAPACITY_WAIT_SECONDS):
            return False
    return True


def publish(channel, queue_name, task, priority, config):
    if not wait_for_queue_capacity(channel, queue_name, config):
        return False
    channel.basic_publish(
        exchange='',
        routing_key=queue_name,
        body=json_util.dumps(task).encode('utf-8'),
        properties=pika.BasicProperties(
            delivery_mode=2,
            content_type='application/json',
            priority=max(0, min(priority, config['RABBITMQ_MAX_PRIORITY'])),
        ),
    )
    return True


class LocalGPUProvider:
    def __init__(self, config, base_url=None):
        self.config = config
        self.base_url = (base_url or config['GPU_INFERENCE_BASE_URL']).rstrip('/')
        self.model = config['GPU_MODEL_NAME']
        self.timeout = config['GPU_REQUEST_TIMEOUT_SECONDS']
        self.retries = config['GPU_JSON_RETRIES']
        self.max_output_tokens = config['GPU_MAX_OUTPUT_TOKENS']
        self.start_prompt = config['GPU_START_PROMPT']
        self.messages = None

    def _log_message(self, direction, role, content, **fields):
        log_llm_message(self.config, direction, role, content, inference=self.base_url, **fields)

    @staticmethod
    def _parse_json(content):
        text = (content or '').strip()
        if text.startswith('```'):
            text = text.split('\n', 1)[-1]
            text = text.rsplit('```', 1)[0]
        result = json.loads(text)
        if not isinstance(result, dict):
            raise ValueError('GPU model JSON response must be an object.')
        return result

    def _completion(self, messages, schema=None, schema_name='vulnerability_item'):
        payload = {
            'model': self.model,
            'messages': messages,
            'temperature': 0.1,
            'max_tokens': self.max_output_tokens,
        }
        if schema is not None:
            payload['response_format'] = {
                'type': 'json_schema',
                'json_schema': {
                    'name': schema_name,
                    'strict': True,
                    'schema': schema,
                },
            }
        outgoing = messages[-1] if messages else {}
        self._log_message(
            'request',
            outgoing.get('role', 'unknown'),
            outgoing.get('content', ''),
            schema=schema_name if schema is not None else None,
        )
        response = requests.post(
            self.base_url + '/chat/completions',
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        content = response.json()['choices'][0]['message']['content']
        self._log_message('response', 'assistant', content, schema=schema_name if schema is not None else None)
        return content

    def open_chat(self):
        if not self.start_prompt:
            raise ValueError('GPU_START_PROMPT must be configured when GPU processing is enabled.')
        self.messages = [{'role': 'user', 'content': self.start_prompt}]
        answer = self._completion(self.messages)
        self.messages.append({'role': 'assistant', 'content': answer})

    def close_chat(self):
        self.messages = None

    def generate_item(self, details, language):
        if self.messages is None:
            raise RuntimeError('GPU chat has not been opened.')
        instruction = (
            f'Write one cybersecurity vulnerability report item in {language}. '
            'Use only the provided JSON details. Do not invent facts. Preserve identifiers and '
            'URLs. Do not return highlight.title. Include highlight.table only when structured '
            'comparison is clearer than prose. Return valid JSON only.'
        )
        base_prompt = instruction + '\nReview details:' + json.dumps(
            details,
            ensure_ascii=False,
            separators=(',', ':'),
            default=str,
        )
        self.messages.append({'role': 'user', 'content': base_prompt})
        error = None
        for _ in range(self.retries + 1):
            try:
                answer = self._completion(self.messages, ITEM_SCHEMA)
                self.messages.append({'role': 'assistant', 'content': answer})
                result = self._parse_json(answer)
                validate(instance=result, schema=ITEM_SCHEMA)
                return result
            except (KeyError, ValueError, ValidationError, requests.RequestException) as exc:
                error = exc
                self.messages.append({
                    'role': 'user',
                    'content': f'The previous response was invalid: {exc}. Return corrected JSON only.',
                })
        raise RuntimeError(str(error))

    def generate_final(self, item_results, language, prompt_template):
        if self.messages is None:
            raise RuntimeError('GPU chat has not been opened.')
        instruction = prompt_template.replace('${language}', language)
        prompt = instruction + '\nProcessed review results:' + json.dumps(
            item_results, ensure_ascii=False, separators=(',', ':'), default=str,
        )
        self.messages.append({'role': 'user', 'content': prompt})
        error = None
        for _ in range(self.retries + 1):
            try:
                answer = self._completion(self.messages, FINAL_SCHEMA, 'report_final_summary')
                self.messages.append({'role': 'assistant', 'content': answer})
                result = self._parse_json(answer)
                validate(instance=result, schema=FINAL_SCHEMA)
                return result
            except (KeyError, ValueError, ValidationError, requests.RequestException) as exc:
                error = exc
                self.messages.append({
                    'role': 'user',
                    'content': f'The previous response was invalid: {exc}. Return corrected JSON only.',
                })
        raise RuntimeError(str(error))


def claim_task(collection, task, owner, config):
    path = _language_path(task['language'])
    stale_before = _now() - timedelta(seconds=config['COMPANY_AI_STALE_PROCESSING_SECONDS'])
    document = collection.find_one_and_update(
        {
            '_id': task['source_id'],
            f'{path}.content_hash': task['content_hash'],
            '$or': [
                {f'{path}.status': {'$in': ['pending', 'failed']}},
                {
                    f'{path}.status': 'processing',
                    f'{path}.processing_started_at': {'$lte': stale_before},
                },
            ],
        },
        {
            '$set': {
                f'{path}.status': 'processing',
                f'{path}.processing_owner': owner,
                f'{path}.processing_started_at': _now(),
                f'{path}.updated_at': _now(),
            },
            '$inc': {f'{path}.attempts': 1},
            '$unset': {f'{path}.error': ''},
        },
        return_document=ReturnDocument.AFTER,
    )
    return ((document or {}).get('html_json') or {}).get(task['language'])


def update_task(collection, task, owner, values, unset_fields):
    path = _language_path(task['language'])
    collection.update_one(
        {'_id': task['source_id'], f'{path}.processing_owner': owner},
        {
            '$set': {f'{path}.{key}': value for key, value in values.items()},
            '$unset': {f'{path}.{key}': '' for key in unset_fields},
        },
    )


def claim_shared_task(collection, task, owner, config):
    stale_before = _now() - timedelta(seconds=config['COMPANY_AI_STALE_PROCESSING_SECONDS'])
    return collection.find_one_and_update(
        {
            '_id': task['task_id'],
            'content_hash': task['content_hash'],
            '$or': [
                {'status': {'$in': ['pending', 'failed']}},
                {'status': 'processing', 'processing_started_at': {'$lte': stale_before}},
            ],
        },
        {
            '$set': {
                'status': 'processing',
                'processing_owner': owner,
                'processing_started_at': _now(),
                'updated_at': _now(),
            },
            '$inc': {'attempts': 1},
            '$unset': {'error': ''},
        },
        return_document=ReturnDocument.AFTER,
    )


def update_shared_task(collection, task, owner, values, unset_fields):
    collection.update_one(
        {'_id': task['task_id'], 'processing_owner': owner},
        {'$set': values, '$unset': {field: '' for field in unset_fields}},
    )


def process_task(database, channel, task, owner, provider, config, worker_number):
    shared = task.get('storage') == 'shared'
    task_type = task.get('task_type', 'item')
    target = _task_target(task)
    collection = database[
        config['AI_TASK_COLLECTION'] if shared else task['source_collection']
    ]
    claimed = (
        claim_shared_task(collection, task, owner, config)
        if shared else claim_task(collection, task, owner, config)
    )
    if claimed is None:
        log_info(
            'Skipped stale task',
            worker=worker_number,
            provider='gpu_local',
            task_type=task_type,
            language=task.get('language'),
            target=target,
        )
        return
    started = time.monotonic()
    try:
        log_info(
            'Processing task',
            worker=worker_number,
            provider='gpu_local',
            inference=getattr(provider, 'base_url', None),
            task_type=task_type,
            language=task['language'],
            target=target,
            attempt=claimed.get('attempts'),
        )
        provider.open_chat()
        if shared:
            details = claimed.get('payload')
        else:
            document = collection.find_one({'_id': task['source_id']}, {'details': 1})
            details = compact_details((document or {}).get('details'), config)
        if summary_content_hash(details, task['language'], config) != task['content_hash']:
            raise ValueError('Source details changed while the task was queued.')
        if task_type == 'final':
            result = provider.generate_final(
                details['item_results'],
                REPORT_LANGUAGES[task['language']],
                config['GPU_FINAL_SUMMARY_PROMPT'],
            )
        else:
            result = provider.generate_item(details, REPORT_LANGUAGES[task['language']])
        updater = update_shared_task if shared else update_task
        updater(
            collection,
            task,
            owner,
            {
                'status': 'completed',
                'result': result,
                'provider': 'gpu_local',
                'completed_at': _now(),
                'updated_at': _now(),
            },
            ['processing_owner', 'processing_started_at', 'error'],
        )
        log_info(
            'Task completed',
            worker=worker_number,
            provider='gpu_local',
            task_type=task_type,
            language=task['language'],
            target=target,
            seconds=round(time.monotonic() - started, 1),
        )
    except Exception as exc:
        updater = update_shared_task if shared else update_task
        updater(
            collection,
            task,
            owner,
            {'status': 'pending', 'error': str(exc), 'updated_at': _now()},
            ['processing_owner', 'processing_started_at'],
        )
        republish_queue = None
        if claimed.get('attempts', 0) >= config['GPU_MAX_TASK_ATTEMPTS']:
            if config['COMPANY_AI_ENABLED']:
                republish_queue = config['RABBITMQ_COMPANY_QUEUE']
        elif config['GPU_ENABLED']:
            republish_queue = config['RABBITMQ_GPU_QUEUE']
        if republish_queue:
            publish(channel, republish_queue, task, config['RABBITMQ_BACKGROUND_PRIORITY'], config)
            log_error(
                'Task failed; republished',
                worker=worker_number,
                provider='gpu_local',
                task_type=task_type,
                language=task.get('language'),
                target=target,
                attempt=claimed.get('attempts'),
                queue=republish_queue,
                error=str(exc),
                seconds=round(time.monotonic() - started, 1),
            )
        else:
            log_error(
                'Task failed',
                worker=worker_number,
                provider='gpu_local',
                task_type=task_type,
                language=task.get('language'),
                target=target,
                attempt=claimed.get('attempts'),
                error=str(exc),
                seconds=round(time.monotonic() - started, 1),
            )
    finally:
        provider.close_chat()


def reset_gpu_processing(database, config):
    now = _now()
    stale_before = now - timedelta(seconds=config['COMPANY_AI_STALE_PROCESSING_SECONDS'])
    for metadata in database.list_collections(filter={'type': 'collection'}):
        collection_name = metadata['name']
        if collection_name.startswith('system.') or collection_name == config['AI_TASK_COLLECTION']:
            continue
        for language in REPORT_LANGUAGES:
            path = _language_path(language)
            database[collection_name].update_many(
                {
                    f'{path}.status': 'processing',
                    f'{path}.processing_owner': {'$regex': '^gpu:'},
                    f'{path}.processing_started_at': {'$lte': stale_before},
                },
                {
                    '$set': {f'{path}.status': 'pending', f'{path}.updated_at': now},
                    '$unset': {f'{path}.processing_owner': '', f'{path}.processing_started_at': ''},
                },
            )
    database[config['AI_TASK_COLLECTION']].update_many(
        {
            'status': 'processing',
            'processing_owner': {'$regex': '^gpu:'},
            'processing_started_at': {'$lte': stale_before},
        },
        {
            '$set': {'status': 'pending', 'updated_at': now},
            '$unset': {'processing_owner': '', 'processing_started_at': ''},
        },
    )


def consume(config, worker_number):
    owner = f'gpu:{uuid.uuid4()}:{worker_number}'
    base_url = inference_base_url_for_worker(config, worker_number)
    client = MongoClient(config['ATLAS_MONGO_URI'], serverSelectionTimeoutMS=5000)
    database = client[config['VULNERABILITIES_DATABASE']]
    provider = LocalGPUProvider(config, base_url=base_url)
    log_info(
        'GPU worker bound to inference endpoint',
        worker=worker_number,
        inference=base_url,
        slot=f'{worker_number + 1}/{config["GPU_WORKER_CONCURRENCY"]}',
    )
    while not STOP_EVENT.is_set():
        connection = None
        try:
            connection = pika.BlockingConnection(pika.URLParameters(config['RABBITMQ_URL']))
            channel = connection.channel()
            gpu_status = declare_queues(channel, config)
            log_info(
                'GPU worker connected',
                worker=worker_number,
                queue=config['RABBITMQ_GPU_QUEUE'],
                messages=gpu_status.method.message_count,
            )
            channel.confirm_delivery()
            channel.basic_qos(prefetch_count=1)
            for method, _, body in channel.consume(
                config['RABBITMQ_GPU_QUEUE'],
                inactivity_timeout=1,
            ):
                if STOP_EVENT.is_set():
                    break
                if method is None:
                    continue
                task = json_util.loads(body.decode('utf-8'))
                received_fields = {
                    'worker': worker_number,
                    'target': _task_target(task),
                    'task_type': task.get('task_type', 'item'),
                    'language': task.get('language'),
                }
                if config.get('GPU_LOG_MESSAGES'):
                    received_fields['body'] = _preview_bytes(
                        body,
                        config['GPU_LOG_MESSAGE_CHARS'],
                    )
                log_info('Received queue message', **received_fields)
                process_task(
                    database,
                    channel,
                    task,
                    owner,
                    provider,
                    config,
                    worker_number,
                )
                channel.basic_ack(method.delivery_tag)
        except Exception as exc:
            log_error(
                'GPU worker reconnecting after error',
                worker=worker_number,
                error=str(exc),
            )
            STOP_EVENT.wait(5)
        finally:
            if connection is not None and connection.is_open:
                connection.close()
    client.close()


def _request_shutdown(*_):
    stop_llama_servers()
    STOP_EVENT.set()


def main():
    atexit.register(stop_llama_servers)
    signal.signal(signal.SIGINT, _request_shutdown)
    signal.signal(signal.SIGTERM, _request_shutdown)
    config = load_config()
    client = MongoClient(config['ATLAS_MONGO_URI'], serverSelectionTimeoutMS=5000)
    database = client[config['VULNERABILITIES_DATABASE']]
    reset_gpu_processing(database, config)
    inference_urls = config['GPU_INFERENCE_BASE_URLS']
    log_info(
        'GPU worker configuration',
        instances=config['GPU_INSTANCE_COUNT'],
        concurrency=config['GPU_WORKER_CONCURRENCY'],
        in_docker=_running_in_docker(),
        urls=','.join(inference_urls),
    )
    if config['GPU_WORKER_CONCURRENCY'] != config['GPU_INSTANCE_COUNT']:
        log_info(
            'WARNING: GPU_WORKER_CONCURRENCY does not match GPU_INSTANCE_COUNT; '
            'per-GPU mode expects one worker per llama-server instance',
            concurrency=config['GPU_WORKER_CONCURRENCY'],
            instances=config['GPU_INSTANCE_COUNT'],
        )
    unresolved = validate_inference_urls(inference_urls)
    for issue in unresolved:
        log_error(
            'Inference endpoint hostname does not resolve',
            worker=issue['worker'],
            url=issue['url'],
            hostname=issue['hostname'],
            hint=(
                'Use GPU_INFERENCE_BASE_URLS=http://host.docker.internal:8080/v1,... when '
                'running gpu-worker in Docker with published llama ports, '
                'http://127.0.0.1:8080/v1,... on the host, or compose service names '
                'llama-server-0:8080 when llama containers share the compose network.'
            ),
        )
    if unresolved:
        raise SystemExit(1)
    if _should_auto_start_llama_servers(config, inference_urls):
        log_info('Auto-starting native llama-server processes on localhost')
        start_llama_servers(config)
    startup_wait_seconds = config['GPU_INFERENCE_STARTUP_WAIT_SECONDS']
    startup_poll_seconds = config['GPU_INFERENCE_STARTUP_POLL_SECONDS']
    if startup_wait_seconds > 0:
        log_info(
            'Checking inference endpoint health',
            wait_seconds=startup_wait_seconds,
            poll_seconds=startup_poll_seconds,
        )
    unreachable = wait_for_inference_urls(
        inference_urls,
        startup_wait_seconds,
        startup_poll_seconds,
    )
    for issue in unreachable:
        status_code = issue.get('status_code')
        if status_code in {502, 503}:
            hint = (
                'Llama server returned HTTP '
                f'{status_code}; model may still be loading or failed to load. '
                'Check: docker compose logs llama-server-0. '
                'A 30B model often will not fit on one 8GB GPU — use a smaller model '
                'or tensor-split mode.'
            )
        elif 'Connection refused' in issue.get('error', ''):
            hint = (
                'No process is listening on that port. Start llama servers manually, '
                'set GPU_LLAMA_SERVER_BIN for native auto-start, or run: '
                'docker compose --profile per-gpu up -d llama-server-0 '
                'llama-server-1 llama-server-2'
            )
        else:
            hint = (
                'Set GPU_INSTANCE_COUNT=1 and GPU_WORKER_CONCURRENCY=1 if only one '
                'GPU/server is running, or increase GPU_INFERENCE_STARTUP_WAIT_SECONDS '
                'while large models load.'
            )
        log_error(
            'Inference endpoint is not reachable',
            worker=issue['worker'],
            url=issue['url'],
            health=issue['health_url'],
            error=issue['error'],
            hint=hint,
        )
    if unreachable:
        raise SystemExit(1)
    if not config['GPU_ENABLED']:
        log_info('GPU processing is disabled; waiting for shutdown')
        try:
            while not STOP_EVENT.wait(1):
                pass
        finally:
            stop_llama_servers()
            reset_gpu_processing(database, config)
            client.close()
        return
    threads = [
        threading.Thread(target=consume, args=(config, number), daemon=True)
        for number in range(config['GPU_WORKER_CONCURRENCY'])
    ]
    try:
        for thread in threads:
            thread.start()
        while not STOP_EVENT.wait(1):
            pass
        for thread in threads:
            thread.join()
    finally:
        stop_llama_servers()
        reset_gpu_processing(database, config)
        client.close()


if __name__ == '__main__':
    main()

import hashlib
import html
import json
import os
import signal
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pika
import requests
from bson import json_util
from jsonschema import ValidationError, validate
from pymongo import MongoClient, ReturnDocument


STOP_EVENT = threading.Event()
REPORT_LANGUAGES = {
    'en': 'English',
    'zh': 'Traditional Chinese',
    'ch': 'Simplified Chinese',
}
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


def _env_int(name, default):
    return int(os.environ.get(name, default))


def _env_bool(name, default):
    value = os.environ.get(name)
    if value is None:
        return bool(default)
    return value.lower() in {'1', 'true', 'yes', 'on'}


def _env_list(name, default):
    value = os.environ.get(name)
    if not value:
        return list(default)
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass
    return [item.strip() for item in value.split(',') if item.strip()]


def load_config():
    required = ['ATLAS_MONGO_URI', 'RABBITMQ_URL']
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise ValueError(f'Missing required environment variables: {", ".join(missing)}')
    return {
        'ATLAS_MONGO_URI': os.environ['ATLAS_MONGO_URI'],
        'VULNERABILITIES_DATABASE': os.environ.get(
            'VULNERABILITIES_DATABASE',
            'vulnerabilities',
        ),
        'AI_TASK_COLLECTION': os.environ.get('AI_TASK_COLLECTION', 'ai_generation_tasks'),
        'RABBITMQ_URL': os.environ['RABBITMQ_URL'],
        'RABBITMQ_GPU_QUEUE': os.environ.get('RABBITMQ_GPU_QUEUE', 'gpu_preprocessing'),
        'RABBITMQ_COMPANY_QUEUE': os.environ.get(
            'RABBITMQ_COMPANY_QUEUE',
            'company_ai_processing',
        ),
        'RABBITMQ_MAX_PRIORITY': _env_int('RABBITMQ_MAX_PRIORITY', 10),
        'RABBITMQ_BACKGROUND_PRIORITY': _env_int('RABBITMQ_BACKGROUND_PRIORITY', 1),
        'GPU_ENABLED': _env_bool('GPU_ENABLED', True),
        'COMPANY_AI_ENABLED': _env_bool('COMPANY_AI_ENABLED', True),
        'GPU_WORKER_CONCURRENCY': _env_int('GPU_WORKER_CONCURRENCY', 1),
        'GPU_MAX_TASK_ATTEMPTS': _env_int('GPU_MAX_TASK_ATTEMPTS', 2),
        'GPU_INFERENCE_BASE_URL': os.environ.get(
            'GPU_INFERENCE_BASE_URL',
            'http://llama-server:8080/v1',
        ).rstrip('/'),
        'GPU_MODEL_NAME': os.environ.get('GPU_MODEL_NAME', 'qwen-local'),
        'GPU_REQUEST_TIMEOUT_SECONDS': _env_int('GPU_REQUEST_TIMEOUT_SECONDS', 300),
        'GPU_JSON_RETRIES': _env_int('GPU_JSON_RETRIES', 2),
        'GPU_MAX_OUTPUT_TOKENS': _env_int('GPU_MAX_OUTPUT_TOKENS', 4096),
        'GPU_START_PROMPT': os.environ.get('GPU_START_PROMPT', ''),
        'GPU_FINAL_SUMMARY_PROMPT': os.environ.get(
            'GPU_FINAL_SUMMARY_PROMPT',
            'Write the final cybersecurity report summary in ${language}.',
        ),
        'PREPROCESSING_CACHE_VERSION': os.environ.get('PREPROCESSING_CACHE_VERSION', '1'),
        'COMPANY_AI_STALE_PROCESSING_SECONDS': _env_int(
            'COMPANY_AI_STALE_PROCESSING_SECONDS',
            900,
        ),
        'REPORT_DENY_KEYS': _env_list(
            'REPORT_DENY_KEYS',
            ['raw', 'raw_fields', 'raw_sections', 'raw_tables'],
        ),
        'REPORT_DENY_PREFIXES': _env_list('REPORT_DENY_PREFIXES', ['raw_']),
        'REPORT_MAX_DEPTH': _env_int('REPORT_MAX_DEPTH', 6),
        'REPORT_MAX_LIST_ITEMS': _env_int('REPORT_MAX_LIST_ITEMS', 100),
        'REPORT_MAX_STRING_CHARS': _env_int('REPORT_MAX_STRING_CHARS', 12000),
    }


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


def declare_queues(channel, config):
    channel.queue_declare(
        queue=config['RABBITMQ_COMPANY_QUEUE'],
        durable=True,
        arguments={'x-max-priority': config['RABBITMQ_MAX_PRIORITY']},
    )
    return channel.queue_declare(
        queue=config['RABBITMQ_GPU_QUEUE'],
        durable=True,
        arguments={'x-max-priority': config['RABBITMQ_MAX_PRIORITY']},
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
        print(f'Unable to clear GPU preprocessing queue: {exc}', flush=True)
        return False


def publish(channel, queue_name, task, priority, config):
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


class LocalGPUProvider:
    def __init__(self, config):
        self.base_url = config['GPU_INFERENCE_BASE_URL']
        self.model = config['GPU_MODEL_NAME']
        self.timeout = config['GPU_REQUEST_TIMEOUT_SECONDS']
        self.retries = config['GPU_JSON_RETRIES']
        self.max_output_tokens = config['GPU_MAX_OUTPUT_TOKENS']
        self.start_prompt = config['GPU_START_PROMPT']
        self.messages = None

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
        response = requests.post(
            self.base_url + '/chat/completions',
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']

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


def process_task(database, channel, task, owner, provider, config):
    shared = task.get('storage') == 'shared'
    collection = database[
        config['AI_TASK_COLLECTION'] if shared else task['source_collection']
    ]
    claimed = (
        claim_shared_task(collection, task, owner, config)
        if shared else claim_task(collection, task, owner, config)
    )
    if claimed is None:
        return
    try:
        provider.open_chat()
        if shared:
            details = claimed.get('payload')
        else:
            document = collection.find_one({'_id': task['source_id']}, {'details': 1})
            details = compact_details((document or {}).get('details'), config)
        if summary_content_hash(details, task['language'], config) != task['content_hash']:
            raise ValueError('Source details changed while the task was queued.')
        if task.get('task_type', 'item') == 'final':
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
    except Exception as exc:
        updater = update_shared_task if shared else update_task
        updater(
            collection,
            task,
            owner,
            {'status': 'pending', 'error': str(exc), 'updated_at': _now()},
            ['processing_owner', 'processing_started_at'],
        )
        target = None
        if claimed.get('attempts', 0) >= config['GPU_MAX_TASK_ATTEMPTS']:
            if config['COMPANY_AI_ENABLED']:
                target = config['RABBITMQ_COMPANY_QUEUE']
        elif config['GPU_ENABLED']:
            target = config['RABBITMQ_GPU_QUEUE']
        if target:
            publish(channel, target, task, config['RABBITMQ_BACKGROUND_PRIORITY'], config)
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
    client = MongoClient(config['ATLAS_MONGO_URI'], serverSelectionTimeoutMS=5000)
    database = client[config['VULNERABILITIES_DATABASE']]
    provider = LocalGPUProvider(config)
    while not STOP_EVENT.is_set():
        connection = None
        try:
            connection = pika.BlockingConnection(pika.URLParameters(config['RABBITMQ_URL']))
            channel = connection.channel()
            declare_queues(channel, config)
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
                process_task(
                    database,
                    channel,
                    json_util.loads(body.decode('utf-8')),
                    owner,
                    provider,
                    config,
                )
                channel.basic_ack(method.delivery_tag)
        except Exception as exc:
            print(f'GPU worker {worker_number} reconnecting after error: {exc}', flush=True)
            STOP_EVENT.wait(5)
        finally:
            if connection is not None and connection.is_open:
                connection.close()
    client.close()


def main():
    signal.signal(signal.SIGINT, lambda *_: STOP_EVENT.set())
    signal.signal(signal.SIGTERM, lambda *_: STOP_EVENT.set())
    config = load_config()
    client = MongoClient(config['ATLAS_MONGO_URI'], serverSelectionTimeoutMS=5000)
    database = client[config['VULNERABILITIES_DATABASE']]
    reset_gpu_processing(database, config)
    if not config['GPU_ENABLED']:
        print('GPU processing is disabled; waiting for shutdown.', flush=True)
        try:
            while not STOP_EVENT.wait(1):
                pass
        finally:
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
        reset_gpu_processing(database, config)
        client.close()


if __name__ == '__main__':
    main()

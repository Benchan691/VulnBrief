import json
import os
import time


def _agent_debug_log(location, message, data, hypothesis_id, run_id='pre-fix'):
    payload = {
        'sessionId': '45cf15',
        'timestamp': int(time.time() * 1000),
        'location': location,
        'message': message,
        'data': data,
        'hypothesisId': hypothesis_id,
        'runId': run_id,
    }
    # #region agent log
    debug_log = os.environ.get('AGENT_DEBUG_LOG', '')
    if not debug_log:
        base = os.path.dirname(os.path.abspath(__file__))
        debug_log = os.path.normpath(os.path.join(base, '..', '.cursor', 'debug-45cf15.log'))
    try:
        log_dir = os.path.dirname(debug_log)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        with open(debug_log, 'a', encoding='utf-8') as handle:
            handle.write(json.dumps(payload) + '\n')
    except OSError:
        pass
    # #endregion


def _gpu_server_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _require_env(*names):
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        raise ValueError(
            'Missing required environment variable(s): ' + ', '.join(missing),
        )


def _coerce_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).lower() in {'1', 'true', 'yes', 'on'}


def _env_override(name, current):
    value = os.environ.get(name)
    if value is None or value == '':
        return current
    return value


def _env_override_int(name, current):
    value = os.environ.get(name)
    if value is None or value == '':
        return int(current)
    return int(value)


def _env_override_bool(name, current):
    value = os.environ.get(name)
    if value is None or value == '':
        return _coerce_bool(current)
    return _coerce_bool(value)


def _env_override_list(name, current):
    value = os.environ.get(name)
    if value is None or value == '':
        return list(current)
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass
    return [item.strip() for item in value.split(',') if item.strip()]


def resolve_inference_base_urls(inference, running_in_docker):
    explicit = inference.get('inference_base_urls')
    if explicit:
        return [url.strip().rstrip('/') for url in explicit if str(url).strip()]

    env_explicit = os.environ.get('GPU_INFERENCE_BASE_URLS', '').strip()
    if env_explicit:
        return [url.strip().rstrip('/') for url in env_explicit.split(',') if url.strip()]

    instance_count = int(inference.get('instance_count', 1))
    if instance_count <= 1:
        if running_in_docker():
            default_url = inference.get('docker_base_url', 'http://host.docker.internal:8080/v1')
        else:
            default_url = inference.get('base_url', 'http://127.0.0.1:8080/v1')
        return [str(_env_override('GPU_INFERENCE_BASE_URL', default_url)).rstrip('/')]

    host_override = os.environ.get('GPU_INFERENCE_HOST', '').strip() or inference.get('host', '').strip()
    base_port = int(_env_override_int('GPU_INFERENCE_BASE_PORT', inference.get('base_port', 8080)))
    if host_override:
        return [
            f'http://{host_override}:{base_port + index}/v1'
            for index in range(instance_count)
        ]

    if not running_in_docker():
        return [
            f'http://127.0.0.1:{base_port + index}/v1'
            for index in range(instance_count)
        ]

    return [f'http://llama-server-{index}:8080/v1' for index in range(instance_count)]


def load_gpu_server_config(base_dir=None, running_in_docker=None):
    base_dir = base_dir or _gpu_server_dir()
    config_path = os.environ.get('GPU_SERVER_CONFIG', os.path.join('config', 'gpu_server.json'))
    if not os.path.isabs(config_path):
        config_path = os.path.join(base_dir, config_path)

    with open(config_path, encoding='utf-8') as handle:
        raw = json.load(handle)

    # #region agent log
    _agent_debug_log(
        'gpu_config.py:load',
        'Loaded GPU server config',
        {
            'config_path': config_path,
            'config_exists': os.path.isfile(config_path),
            'instance_count': raw.get('inference', {}).get('instance_count'),
            'tensor_split': raw.get('inference', {}).get('tensor_split'),
            'gpu_queue': raw.get('rabbitmq', {}).get('gpu_queue'),
        },
        'A',
    )
    # #endregion

    inference = raw.get('inference', {})
    rabbitmq = raw.get('rabbitmq', {})
    mongodb = raw.get('mongodb', {})
    processing = raw.get('processing', {})
    prompts = raw.get('prompts', {})
    report = raw.get('report_compaction', {})
    flags = raw.get('flags', {})

    if running_in_docker is None:
        if os.environ.get('GPU_INFERENCE_NETWORK', '').strip().lower() == 'docker':
            running_in_docker = lambda: True
        else:
            running_in_docker = lambda: os.path.exists('/.dockerenv')

    inference_urls = resolve_inference_base_urls(inference, running_in_docker)
    instance_count = len(inference_urls)
    worker_concurrency = int(
        _env_override_int(
            'GPU_WORKER_CONCURRENCY',
            inference.get('worker_concurrency', instance_count if instance_count > 1 else 1),
        )
    )

    _require_env('ATLAS_MONGO_URI', 'RABBITMQ_URL')

    return {
        'ATLAS_MONGO_URI': os.environ['ATLAS_MONGO_URI'],
        'RABBITMQ_URL': os.environ['RABBITMQ_URL'],
        'VULNERABILITIES_DATABASE': _env_override(
            'VULNERABILITIES_DATABASE',
            mongodb.get('vulnerabilities_database', 'vulnerabilities'),
        ),
        'AI_TASK_COLLECTION': _env_override(
            'AI_TASK_COLLECTION',
            mongodb.get('ai_task_collection', 'ai_generation_tasks'),
        ),
        'RABBITMQ_GPU_QUEUE': _env_override(
            'RABBITMQ_GPU_QUEUE',
            rabbitmq.get('gpu_queue', 'gpu_processing'),
        ),
        'RABBITMQ_COMPANY_QUEUE': _env_override(
            'RABBITMQ_COMPANY_QUEUE',
            rabbitmq.get('company_queue', 'company_ai_processing'),
        ),
        'RABBITMQ_MAX_PRIORITY': _env_override_int(
            'RABBITMQ_MAX_PRIORITY',
            rabbitmq.get('max_priority', 10),
        ),
        'RABBITMQ_MAX_QUEUE_SIZE': _env_override_int(
            'RABBITMQ_MAX_QUEUE_SIZE',
            rabbitmq.get('max_queue_size', 19999),
        ),
        'RABBITMQ_BACKGROUND_PRIORITY': _env_override_int(
            'RABBITMQ_BACKGROUND_PRIORITY',
            rabbitmq.get('background_priority', 1),
        ),
        'GPU_ENABLED': _env_override_bool('GPU_ENABLED', flags.get('gpu_enabled', True)),
        'COMPANY_AI_ENABLED': _env_override_bool(
            'COMPANY_AI_ENABLED',
            flags.get('company_ai_enabled', True),
        ),
        'GPU_INSTANCE_COUNT': instance_count,
        'GPU_INFERENCE_BASE_URLS': inference_urls,
        'GPU_WORKER_CONCURRENCY': worker_concurrency,
        'GPU_MAX_TASK_ATTEMPTS': _env_override_int(
            'GPU_MAX_TASK_ATTEMPTS',
            processing.get('max_task_attempts', 2),
        ),
        'GPU_INFERENCE_BASE_URL': inference_urls[0],
        'GPU_MODEL_NAME': _env_override('GPU_MODEL_NAME', inference.get('model_name', 'qwen-local')),
        'GPU_MODEL_PATH': _env_override('GPU_MODEL_PATH', inference.get('model_path', '')),
        'GPU_CONTEXT_SIZE': _env_override_int(
            'GPU_CONTEXT_SIZE',
            inference.get('context_size', 4096),
        ),
        'GPU_TENSOR_SPLIT': _env_override(
            'GPU_TENSOR_SPLIT',
            inference.get('tensor_split', '1,1,1'),
        ),
        'GPU_INFERENCE_BASE_PORT': _env_override_int(
            'GPU_INFERENCE_BASE_PORT',
            inference.get('base_port', 8080),
        ),
        'GPU_AUTO_START_LLAMA_SERVERS': _env_override_bool(
            'GPU_AUTO_START_LLAMA_SERVERS',
            inference.get('auto_start_llama_servers', True),
        ),
        'GPU_REQUEST_TIMEOUT_SECONDS': _env_override_int(
            'GPU_REQUEST_TIMEOUT_SECONDS',
            inference.get('request_timeout_seconds', 300),
        ),
        'GPU_JSON_RETRIES': _env_override_int(
            'GPU_JSON_RETRIES',
            inference.get('json_retries', 2),
        ),
        'GPU_MAX_OUTPUT_TOKENS': _env_override_int(
            'GPU_MAX_OUTPUT_TOKENS',
            inference.get('max_output_tokens', 4096),
        ),
        'GPU_LLAMA_LOG_VERBOSITY': _env_override_int(
            'GPU_LLAMA_LOG_VERBOSITY',
            inference.get('llama_log_verbosity', 1),
        ),
        'GPU_LOG_MESSAGES': _env_override_bool(
            'GPU_LOG_MESSAGES',
            inference.get('log_messages', True),
        ),
        'GPU_LOG_MESSAGE_CHARS': _env_override_int(
            'GPU_LOG_MESSAGE_CHARS',
            inference.get('log_message_chars', 2000),
        ),
        'GPU_INFERENCE_STARTUP_WAIT_SECONDS': _env_override_int(
            'GPU_INFERENCE_STARTUP_WAIT_SECONDS',
            inference.get('startup_wait_seconds', 600),
        ),
        'GPU_INFERENCE_STARTUP_POLL_SECONDS': _env_override_int(
            'GPU_INFERENCE_STARTUP_POLL_SECONDS',
            inference.get('startup_poll_seconds', 5),
        ),
        'GPU_START_PROMPT': _env_override('GPU_START_PROMPT', prompts.get('start_prompt', '')),
        'GPU_FINAL_SUMMARY_PROMPT': _env_override(
            'GPU_FINAL_SUMMARY_PROMPT',
            prompts.get(
                'final_summary_prompt',
                'Write the final cybersecurity report summary in ${language}.',
            ),
        ),
        'PREPROCESSING_CACHE_VERSION': _env_override(
            'PREPROCESSING_CACHE_VERSION',
            processing.get('cache_version', '1'),
        ),
        'COMPANY_AI_STALE_PROCESSING_SECONDS': _env_override_int(
            'COMPANY_AI_STALE_PROCESSING_SECONDS',
            processing.get('stale_processing_seconds', 900),
        ),
        'REPORT_DENY_KEYS': _env_override_list(
            'REPORT_DENY_KEYS',
            report.get('deny_keys', ['raw', 'raw_fields', 'raw_sections', 'raw_tables']),
        ),
        'REPORT_DENY_PREFIXES': _env_override_list(
            'REPORT_DENY_PREFIXES',
            report.get('deny_prefixes', ['raw_']),
        ),
        'REPORT_MAX_DEPTH': _env_override_int('REPORT_MAX_DEPTH', report.get('max_depth', 6)),
        'REPORT_MAX_LIST_ITEMS': _env_override_int(
            'REPORT_MAX_LIST_ITEMS',
            report.get('max_list_items', 100),
        ),
        'REPORT_MAX_STRING_CHARS': _env_override_int(
            'REPORT_MAX_STRING_CHARS',
            report.get('max_string_chars', 12000),
        ),
    }

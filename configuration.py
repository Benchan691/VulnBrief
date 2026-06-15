import json
import os


def _env_str(name, default):
    return os.environ.get(name, default)


def _env_int(name, default):
    value = os.environ.get(name)
    return int(value) if value is not None else int(default)


def _env_float(name, default):
    value = os.environ.get(name)
    return float(value) if value is not None else float(default)


def _env_bool(name, default):
    value = os.environ.get(name)
    if value is None:
        if isinstance(default, str):
            return default.lower() in {'1', 'true', 'yes', 'on'}
        return bool(default)
    return str(value).lower() in {'1', 'true', 'yes', 'on'}


def _env_json_list(name, default):
    value = os.environ.get(name)
    if value is None or value == '':
        return list(default)
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass
    return [item.strip() for item in value.split(',') if item.strip()]


def _cfg_str(env_name, source, key, default=''):
    return _env_str(env_name, source.get(key, default))


def _cfg_int(env_name, source, key, default):
    return _env_int(env_name, source.get(key, default))


def _cfg_float(env_name, source, key, default):
    return _env_float(env_name, source.get(key, default))


def _cfg_bool(env_name, source, key, default):
    return _env_bool(env_name, source.get(key, default))


def _cfg_json_list(env_name, source, key, default):
    return _env_json_list(env_name, source.get(key, default))


def load_application_config(base_dir, require_local=True):
    config_path = os.environ.get(
        'APP_CONFIG',
        os.path.join(base_dir, 'config', 'config.json'),
    )

    with open(config_path, 'r', encoding='utf-8') as config_file:
        file_config = json.load(config_file)

    company_ai_config = file_config.get('company_ai', {})
    rabbitmq_config = file_config.get('rabbitmq', {})
    preprocessing_config = file_config.get('company_ai_preprocessing', {})
    gpu_config = file_config.get('gpu_preprocessing', {})
    report_config = file_config.get('report_processing', {})
    web_auth_config = file_config.get('web_auth', {})
    scheduler_config = file_config.get('scheduler', {})
    legacy_queue_name = _env_str(
        'RABBITMQ_QUEUE_NAME',
        rabbitmq_config.get('intake_queue', rabbitmq_config.get(
            'queue_name',
            'company_ai_preprocessing',
        )),
    )
    intake_queue = _env_str('RABBITMQ_INTAKE_QUEUE', legacy_queue_name)
    newsletter_root = file_config.get('newsletter_root', 'newsletters')
    sources_config = file_config.get('sources_config', os.path.join('config', 'sources.json'))
    if not os.path.isabs(newsletter_root):
        newsletter_root = os.path.join(base_dir, newsletter_root)
    if not os.path.isabs(sources_config):
        sources_config = os.path.join(base_dir, sources_config)
    atlas_mongo_uri = _env_str(
        'ATLAS_MONGO_URI',
        file_config.get('atlas_mongo_uri', file_config.get('mongo_uri', '')),
    )
    local_mongo_uri = _env_str(
        'LOCAL_MONGO_URI',
        file_config.get('local_mongo_uri', file_config.get('mongo_uri', '')),
    )
    if require_local and (not atlas_mongo_uri or not local_mongo_uri):
        raise ValueError('Both atlas_mongo_uri and local_mongo_uri must be configured.')
    if not atlas_mongo_uri:
        raise ValueError('atlas_mongo_uri must be configured.')

    local_database = file_config.get('local_database', file_config.get('web_database', 'web'))
    report_json_error_message = report_config.get(
        'json_error_message',
        'The JSON above is invalid.\n\nError:\n${error}\n\n'
        'Fix it and return only valid JSON. No Markdown, no explanation, no extra text. '
        'Keep the original fields and meaning. Make only the minimum changes needed so '
        'it can parse with `json.loads()`.',
    )

    return {
        'ATLAS_MONGO_URI': atlas_mongo_uri,
        'LOCAL_MONGO_URI': local_mongo_uri,
        'LOCAL_DATABASE': _env_str('LOCAL_DATABASE', local_database),
        'WEB_DATABASE': _env_str('WEB_DATABASE', local_database),
        'VULNERABILITIES_DATABASE': _env_str(
            'VULNERABILITIES_DATABASE',
            file_config['vulnerabilities_database'],
        ),
        'AI_TASK_COLLECTION': _env_str(
            'AI_TASK_COLLECTION',
            preprocessing_config.get('task_collection', 'ai_generation_tasks'),
        ),
        'REVIEW_VIEW_SUFFIX': _cfg_str('REVIEW_VIEW_SUFFIX', file_config, 'review_view_suffix', '_review'),
        'SECRET_KEY': _env_str('FLASK_SECRET_KEY', file_config['flask_secret_key']),
        'WEB_AUTH_BOOTSTRAP_USERNAME': _cfg_str(
            'WEB_AUTH_BOOTSTRAP_USERNAME', web_auth_config, 'bootstrap_username', 'admin',
        ),
        'WEB_AUTH_BOOTSTRAP_PASSWORD': _cfg_str(
            'WEB_AUTH_BOOTSTRAP_PASSWORD', web_auth_config, 'bootstrap_password', 'changeme',
        ),
        'NEWSLETTER_ROOT': _env_str('NEWSLETTER_ROOT', newsletter_root),
        'SOURCES_CONFIG': _env_str('SOURCES_CONFIG', sources_config),
        'COMPANY_AI_BASE_URL': _cfg_str('COMPANY_AI_BASE_URL', company_ai_config, 'base_url'),
        'COMPANY_AI_USERNAME': _cfg_str('COMPANY_AI_USERNAME', company_ai_config, 'username'),
        'COMPANY_AI_PASSWORD': _cfg_str('COMPANY_AI_PASSWORD', company_ai_config, 'password'),
        'COMPANY_AI_START_PROMPT': _cfg_str('COMPANY_AI_START_PROMPT', company_ai_config, 'start_prompt'),
        'COMPANY_AI_SUMMARY_PROMPT': _cfg_str('COMPANY_AI_SUMMARY_PROMPT', company_ai_config, 'summary_prompt'),
        'COMPANY_AI_PUBLIC_KEY_B64': _cfg_str('COMPANY_AI_PUBLIC_KEY_B64', company_ai_config, 'public_key_b64'),
        'COMPANY_AI_SIGN_SECRET': _cfg_str('COMPANY_AI_SIGN_SECRET', company_ai_config, 'sign_secret'),
        'COMPANY_AI_API_TIMEZONE': _cfg_str(
            'COMPANY_AI_API_TIMEZONE', company_ai_config, 'api_timezone', 'Asia/Shanghai',
        ),
        'COMPANY_AI_SSE_DELAY_SECONDS': _cfg_float(
            'COMPANY_AI_SSE_DELAY_SECONDS', company_ai_config, 'sse_connection_delay_seconds', 2,
        ),
        'COMPANY_AI_MODEL': _cfg_str('COMPANY_AI_MODEL', company_ai_config, 'model'),
        'COMPANY_AI_OWNER_ACCOUNT': _env_str(
            'COMPANY_AI_OWNER_ACCOUNT',
            company_ai_config.get('owner_account', company_ai_config.get('username', '')),
        ),
        'COMPANY_AI_PLATFORM_ID': _cfg_int('COMPANY_AI_PLATFORM_ID', company_ai_config, 'platform_id', 5),
        'COMPANY_AI_QA_TYPE': _cfg_int('COMPANY_AI_QA_TYPE', company_ai_config, 'qa_type', 0),
        'COMPANY_AI_FROM_SOURCE': _cfg_str(
            'COMPANY_AI_FROM_SOURCE', company_ai_config, 'from_source', 'normal_chat',
        ),
        'COMPANY_AI_USE_THINK': _cfg_bool('COMPANY_AI_USE_THINK', company_ai_config, 'use_think', True),
        'COMPANY_AI_USER_PROMPT': _cfg_str('COMPANY_AI_USER_PROMPT', company_ai_config, 'user_prompt'),
        'COMPANY_AI_DATASET_IDS': _cfg_json_list(
            'COMPANY_AI_DATASET_IDS', company_ai_config, 'dataset_ids', [],
        ),
        'COMPANY_AI_FILE_IDS': _cfg_json_list(
            'COMPANY_AI_FILE_IDS', company_ai_config, 'file_ids', [],
        ),
        'COMPANY_AI_CONTEXT_LIMIT': _cfg_int(
            'COMPANY_AI_CONTEXT_LIMIT', company_ai_config, 'context_limit', 32768,
        ),
        'COMPANY_AI_MAX_OUTPUT_TOKENS': _cfg_int(
            'COMPANY_AI_MAX_OUTPUT_TOKENS', company_ai_config, 'max_output_tokens', 4096,
        ),
        'COMPANY_AI_TIMEOUT_SECONDS': _cfg_int(
            'COMPANY_AI_TIMEOUT_SECONDS', company_ai_config, 'timeout_seconds', 180,
        ),
        'COMPANY_AI_RETRIES': _cfg_int('COMPANY_AI_RETRIES', company_ai_config, 'retries', 1),
        'COMPANY_AI_AUTH_TTL_SECONDS': _cfg_int(
            'COMPANY_AI_AUTH_TTL_SECONDS', company_ai_config, 'auth_ttl_seconds', 3600,
        ),
        'COMPANY_AI_LOGIN_MAX_FAILURES': _cfg_int(
            'COMPANY_AI_LOGIN_MAX_FAILURES', company_ai_config, 'login_max_failures', 3,
        ),
        'COMPANY_AI_PARALLEL_CHATS': _cfg_int(
            'COMPANY_AI_PARALLEL_CHATS', company_ai_config, 'parallel_chats', 4,
        ),
        'COMPANY_AI_ENABLED': _cfg_bool('COMPANY_AI_ENABLED', company_ai_config, 'enabled', True),
        'RABBITMQ_URL': _cfg_str(
            'RABBITMQ_URL', rabbitmq_config, 'url', 'amqp://guest:guest@localhost:5672/%2F',
        ),
        'RABBITMQ_INTAKE_QUEUE': _env_str('RABBITMQ_INTAKE_QUEUE', intake_queue),
        'RABBITMQ_QUEUE_NAME': _env_str('RABBITMQ_QUEUE_NAME', intake_queue),
        'RABBITMQ_GPU_QUEUE': _cfg_str(
            'RABBITMQ_GPU_QUEUE', rabbitmq_config, 'gpu_queue', 'gpu_preprocessing',
        ),
        'RABBITMQ_COMPANY_QUEUE': _cfg_str(
            'RABBITMQ_COMPANY_QUEUE', rabbitmq_config, 'company_queue', 'company_ai_processing',
        ),
        'RABBITMQ_MAX_PRIORITY': min(255, _cfg_int(
            'RABBITMQ_MAX_PRIORITY', rabbitmq_config, 'max_priority', 10,
        )),
        'RABBITMQ_BACKGROUND_PRIORITY': _cfg_int(
            'RABBITMQ_BACKGROUND_PRIORITY', rabbitmq_config, 'background_priority', 1,
        ),
        'RABBITMQ_REPORT_PRIORITY': _cfg_int(
            'RABBITMQ_REPORT_PRIORITY', rabbitmq_config, 'report_priority', 10,
        ),
        'COMPANY_AI_SCAN_INTERVAL_SECONDS': _cfg_int(
            'COMPANY_AI_SCAN_INTERVAL_SECONDS', preprocessing_config, 'scan_interval_seconds', 60,
        ),
        'COMPANY_AI_STALE_PROCESSING_SECONDS': _cfg_int(
            'COMPANY_AI_STALE_PROCESSING_SECONDS', preprocessing_config, 'stale_processing_seconds', 900,
        ),
        'COMPANY_AI_REPORT_WAIT_TIMEOUT_SECONDS': _cfg_int(
            'COMPANY_AI_REPORT_WAIT_TIMEOUT_SECONDS',
            preprocessing_config,
            'report_wait_timeout_seconds',
            300,
        ),
        'COMPANY_AI_MAX_TASK_ATTEMPTS': _cfg_int(
            'COMPANY_AI_MAX_TASK_ATTEMPTS', preprocessing_config, 'max_task_attempts', 10,
        ),
        'GPU_QUEUE_BACKLOG_LIMIT': _cfg_int(
            'GPU_QUEUE_BACKLOG_LIMIT', gpu_config, 'queue_backlog_limit', 20,
        ),
        'GPU_ENABLED': _cfg_bool('GPU_ENABLED', gpu_config, 'enabled', False),
        'PREPROCESSING_CACHE_VERSION': _cfg_str(
            'PREPROCESSING_CACHE_VERSION', preprocessing_config, 'cache_version', '1',
        ),
        'GPU_WORKER_CONCURRENCY': _cfg_int(
            'GPU_WORKER_CONCURRENCY', gpu_config, 'worker_concurrency', 1,
        ),
        'GPU_MAX_TASK_ATTEMPTS': _cfg_int(
            'GPU_MAX_TASK_ATTEMPTS', gpu_config, 'max_task_attempts', 2,
        ),
        'GPU_MODEL_PATH': _cfg_str(
            'GPU_MODEL_PATH', gpu_config, 'model_path', '/models/qwen-14b-q4.gguf',
        ),
        'GPU_MODEL_NAME': _cfg_str('GPU_MODEL_NAME', gpu_config, 'model_name', 'qwen-local'),
        'GPU_CONTEXT_SIZE': _cfg_int('GPU_CONTEXT_SIZE', gpu_config, 'context_size', 16384),
        'GPU_TENSOR_SPLIT': _cfg_str('GPU_TENSOR_SPLIT', gpu_config, 'tensor_split', '1,1,1'),
        'GPU_INFERENCE_BASE_URL': _cfg_str(
            'GPU_INFERENCE_BASE_URL', gpu_config, 'inference_base_url', 'http://llama-server:8080/v1',
        ),
        'GPU_START_PROMPT': _env_str(
            'GPU_START_PROMPT',
            gpu_config.get('start_prompt', company_ai_config.get('start_prompt', '')),
        ),
        'GPU_FINAL_SUMMARY_PROMPT': _env_str(
            'GPU_FINAL_SUMMARY_PROMPT',
            gpu_config.get('final_summary_prompt', company_ai_config.get('summary_prompt', '')),
        ),
        'REPORT_ITEM_JSON_RETRIES': _cfg_int(
            'REPORT_ITEM_JSON_RETRIES', report_config, 'item_json_retries', 2,
        ),
        'REPORT_FINAL_JSON_RETRIES': _cfg_int(
            'REPORT_FINAL_JSON_RETRIES', report_config, 'final_json_retries', 2,
        ),
        'REPORT_JSON_ERROR_MESSAGE': _env_str('REPORT_JSON_ERROR_MESSAGE', report_json_error_message),
        'REPORT_DENY_KEYS': _cfg_json_list(
            'REPORT_DENY_KEYS',
            report_config,
            'deny_keys',
            ['raw', 'raw_fields', 'raw_sections', 'raw_tables'],
        ),
        'REPORT_DENY_PREFIXES': _cfg_json_list(
            'REPORT_DENY_PREFIXES', report_config, 'deny_prefixes', ['raw_'],
        ),
        'REPORT_MAX_DEPTH': _cfg_int('REPORT_MAX_DEPTH', report_config, 'max_depth', 6),
        'REPORT_MAX_LIST_ITEMS': _cfg_int(
            'REPORT_MAX_LIST_ITEMS', report_config, 'max_list_items', 100,
        ),
        'REPORT_MAX_STRING_CHARS': _cfg_int(
            'REPORT_MAX_STRING_CHARS', report_config, 'max_string_chars', 12000,
        ),
        'REPORT_PREVIEW_AFTER_EACH_ITEM': _cfg_bool(
            'REPORT_PREVIEW_AFTER_EACH_ITEM', report_config, 'preview_after_each_item', True,
        ),
        'SCHEDULER_SCAN_INTERVAL_SECONDS': _cfg_int(
            'SCHEDULER_SCAN_INTERVAL_SECONDS', scheduler_config, 'scan_interval_seconds', 60,
        ),
    }

import json
import os


DEFAULT_JSON_ERROR_MESSAGE = (
    'The JSON above is invalid.\n\nError:\n${error}\n\n'
    'Fix it and return only valid JSON. No Markdown, no explanation, no extra text. '
    'Keep the original fields and meaning. Make only the minimum changes needed so '
    'it can parse with `json.loads()`.'
)

def _config_file_path(base_dir):
    return os.environ.get('APP_CONFIG', os.path.join(base_dir, 'config', 'config.json'))


def _load_file_config(base_dir):
    path = _config_file_path(base_dir)
    if not os.path.isfile(path):
        return {}
    with open(path, encoding='utf-8') as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f'{path} must contain a JSON object.')
    return data


def _dig(config, *keys):
    node = config
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def _env_set(name):
    value = os.environ.get(name)
    return value is not None and value != ''


def _env_str(name, default=''):
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


def _env_json_dict(name, default):
    value = os.environ.get(name)
    if value is None or value == '':
        return dict(default)
    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    return dict(default)


def _require_env(*names):
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        raise ValueError(
            'Missing required environment variable(s): ' + ', '.join(missing),
        )


def _resolve_str(env_name, file_config, json_keys, default=''):
    if _env_set(env_name):
        return os.environ[env_name]
    file_value = _dig(file_config, *json_keys) if json_keys else None
    if file_value is not None:
        return str(file_value)
    return default


def _resolve_int(env_name, file_config, json_keys, default):
    if _env_set(env_name):
        return _env_int(env_name, default)
    file_value = _dig(file_config, *json_keys) if json_keys else None
    if file_value is not None:
        return int(file_value)
    return int(default)


def _resolve_float(env_name, file_config, json_keys, default):
    if _env_set(env_name):
        return _env_float(env_name, default)
    file_value = _dig(file_config, *json_keys) if json_keys else None
    if file_value is not None:
        return float(file_value)
    return float(default)


def _resolve_bool(env_name, file_config, json_keys, default):
    if _env_set(env_name):
        return _env_bool(env_name, default)
    file_value = _dig(file_config, *json_keys) if json_keys else None
    if file_value is not None:
        if isinstance(file_value, bool):
            return file_value
        return str(file_value).lower() in {'1', 'true', 'yes', 'on'}
    return _env_bool(env_name, default)


def _resolve_list(env_name, file_config, json_keys, default):
    if _env_set(env_name):
        return _env_json_list(env_name, default)
    file_value = _dig(file_config, *json_keys) if json_keys else None
    if isinstance(file_value, list):
        return list(file_value)
    return list(default)


def _resolve_dict(env_name, file_config, json_keys, default):
    if _env_set(env_name):
        return _env_json_dict(env_name, default)
    file_value = _dig(file_config, *json_keys) if json_keys else None
    if isinstance(file_value, dict):
        return dict(file_value)
    return dict(default)


def load_application_config(base_dir, require_local=True):
    file_config = _load_file_config(base_dir)

    local_database = _resolve_str(
        'LOCAL_DATABASE',
        file_config,
        ('mongodb', 'local_database'),
        _resolve_str('WEB_DATABASE', file_config, ('mongodb', 'web_database'), 'web'),
    )
    newsletter_root = _resolve_str('NEWSLETTER_ROOT', file_config, ('newsletter_root',), 'newsletters')
    if not os.path.isabs(newsletter_root):
        newsletter_root = os.path.join(base_dir, newsletter_root)

    atlas_mongo_uri = _env_str('ATLAS_MONGO_URI')
    local_mongo_uri = _env_str('LOCAL_MONGO_URI')
    if require_local:
        _require_env('ATLAS_MONGO_URI', 'LOCAL_MONGO_URI', 'FLASK_SECRET_KEY')
    else:
        _require_env('ATLAS_MONGO_URI')

    legacy_queue_name = _resolve_str(
        'RABBITMQ_QUEUE_NAME',
        file_config,
        ('rabbitmq', 'intake_queue'),
        _resolve_str('RABBITMQ_INTAKE_QUEUE', file_config, ('rabbitmq', 'intake_queue'), 'company_ai_preprocessing'),
    )
    intake_queue = _resolve_str(
        'RABBITMQ_INTAKE_QUEUE',
        file_config,
        ('rabbitmq', 'intake_queue'),
        legacy_queue_name,
    )
    company_ai_start_prompt = _resolve_str(
        'COMPANY_AI_START_PROMPT',
        file_config,
        ('company_ai', 'start_prompt'),
        '',
    )
    company_ai_summary_prompt = _resolve_str(
        'COMPANY_AI_SUMMARY_PROMPT',
        file_config,
        ('company_ai', 'summary_prompt'),
        '',
    )
    company_ai_username = _resolve_str(
        'COMPANY_AI_USERNAME',
        file_config,
        ('company_ai', 'username'),
        '',
    )
    gpu_start_prompt = _resolve_str('GPU_START_PROMPT', file_config, ('gpu', 'start_prompt'), '') or company_ai_start_prompt
    gpu_final_summary_prompt = (
        _resolve_str('GPU_FINAL_SUMMARY_PROMPT', file_config, ('gpu', 'final_summary_prompt'), '')
        or company_ai_summary_prompt
    )

    return {
        'ATLAS_MONGO_URI': atlas_mongo_uri,
        'LOCAL_MONGO_URI': local_mongo_uri,
        'LOCAL_DATABASE': local_database,
        'WEB_DATABASE': _resolve_str(
            'WEB_DATABASE',
            file_config,
            ('mongodb', 'web_database'),
            local_database,
        ),
        'VULNERABILITIES_DATABASE': _resolve_str(
            'VULNERABILITIES_DATABASE',
            file_config,
            ('mongodb', 'vulnerabilities_database'),
            'vulnerabilities',
        ),
        'AI_TASK_COLLECTION': _resolve_str(
            'AI_TASK_COLLECTION',
            file_config,
            ('mongodb', 'ai_task_collection'),
            'ai_generation_tasks',
        ),
        'AI_PROVIDER_METRICS_COLLECTION': _resolve_str(
            'AI_PROVIDER_METRICS_COLLECTION',
            file_config,
            ('mongodb', 'ai_provider_metrics_collection'),
            'ai_provider_metrics',
        ),
        'REVIEW_VIEW_SUFFIX': _resolve_str(
            'REVIEW_VIEW_SUFFIX',
            file_config,
            ('mongodb', 'review_view_suffix'),
            '_review',
        ),
        'SECRET_KEY': _env_str('FLASK_SECRET_KEY'),
        'WEB_AUTH_BOOTSTRAP_USERNAME': _resolve_str(
            'WEB_AUTH_BOOTSTRAP_USERNAME',
            file_config,
            ('web_auth', 'bootstrap_username'),
            'admin',
        ),
        'WEB_AUTH_BOOTSTRAP_PASSWORD': _env_str('WEB_AUTH_BOOTSTRAP_PASSWORD', 'changeme'),
        'NEWSLETTER_ROOT': newsletter_root,
        'COMPANY_AI_BASE_URL': _resolve_str(
            'COMPANY_AI_BASE_URL',
            file_config,
            ('company_ai', 'base_url'),
            '',
        ),
        'COMPANY_AI_USERNAME': company_ai_username,
        'COMPANY_AI_PASSWORD': _env_str('COMPANY_AI_PASSWORD'),
        'COMPANY_AI_START_PROMPT': company_ai_start_prompt,
        'COMPANY_AI_SUMMARY_PROMPT': company_ai_summary_prompt,
        'COMPANY_AI_PUBLIC_KEY_B64': _env_str('COMPANY_AI_PUBLIC_KEY_B64'),
        'COMPANY_AI_SIGN_SECRET': _env_str('COMPANY_AI_SIGN_SECRET'),
        'COMPANY_AI_API_TIMEZONE': _resolve_str(
            'COMPANY_AI_API_TIMEZONE',
            file_config,
            ('company_ai', 'api_timezone'),
            'Asia/Shanghai',
        ),
        'COMPANY_AI_SSE_DELAY_SECONDS': _resolve_float(
            'COMPANY_AI_SSE_DELAY_SECONDS',
            file_config,
            ('company_ai', 'sse_delay_seconds'),
            2,
        ),
        'COMPANY_AI_MODEL': _resolve_str(
            'COMPANY_AI_MODEL',
            file_config,
            ('company_ai', 'model'),
            '',
        ),
        'COMPANY_AI_OWNER_ACCOUNT': _resolve_str(
            'COMPANY_AI_OWNER_ACCOUNT',
            file_config,
            ('company_ai', 'owner_account'),
            company_ai_username,
        ),
        'COMPANY_AI_PLATFORM_ID': _resolve_int(
            'COMPANY_AI_PLATFORM_ID',
            file_config,
            ('company_ai', 'platform_id'),
            5,
        ),
        'COMPANY_AI_QA_TYPE': _resolve_int(
            'COMPANY_AI_QA_TYPE',
            file_config,
            ('company_ai', 'qa_type'),
            0,
        ),
        'COMPANY_AI_FROM_SOURCE': _resolve_str(
            'COMPANY_AI_FROM_SOURCE',
            file_config,
            ('company_ai', 'from_source'),
            'normal_chat',
        ),
        'COMPANY_AI_USE_THINK': _resolve_bool(
            'COMPANY_AI_USE_THINK',
            file_config,
            ('company_ai', 'use_think'),
            True,
        ),
        'COMPANY_AI_USER_PROMPT': _resolve_str(
            'COMPANY_AI_USER_PROMPT',
            file_config,
            ('company_ai', 'user_prompt'),
            '',
        ),
        'COMPANY_AI_DATASET_IDS': _resolve_list(
            'COMPANY_AI_DATASET_IDS',
            file_config,
            ('company_ai', 'dataset_ids'),
            [],
        ),
        'COMPANY_AI_FILE_IDS': _resolve_list(
            'COMPANY_AI_FILE_IDS',
            file_config,
            ('company_ai', 'file_ids'),
            [],
        ),
        'COMPANY_AI_CONTEXT_LIMIT': _resolve_int(
            'COMPANY_AI_CONTEXT_LIMIT',
            file_config,
            ('company_ai', 'context_limit'),
            32768,
        ),
        'COMPANY_AI_MAX_OUTPUT_TOKENS': _resolve_int(
            'COMPANY_AI_MAX_OUTPUT_TOKENS',
            file_config,
            ('company_ai', 'max_output_tokens'),
            4096,
        ),
        'COMPANY_AI_TIMEOUT_SECONDS': _resolve_int(
            'COMPANY_AI_TIMEOUT_SECONDS',
            file_config,
            ('company_ai', 'timeout_seconds'),
            180,
        ),
        'COMPANY_AI_RETRIES': _resolve_int(
            'COMPANY_AI_RETRIES',
            file_config,
            ('company_ai', 'retries'),
            1,
        ),
        'COMPANY_AI_AUTH_TTL_SECONDS': _resolve_int(
            'COMPANY_AI_AUTH_TTL_SECONDS',
            file_config,
            ('company_ai', 'auth_ttl_seconds'),
            3600,
        ),
        'COMPANY_AI_LOGIN_MAX_FAILURES': _resolve_int(
            'COMPANY_AI_LOGIN_MAX_FAILURES',
            file_config,
            ('company_ai', 'login_max_failures'),
            3,
        ),
        'COMPANY_AI_PARALLEL_CHATS': _resolve_int(
            'COMPANY_AI_PARALLEL_CHATS',
            file_config,
            ('company_ai', 'parallel_chats'),
            4,
        ),
        'COMPANY_AI_ENABLED': _resolve_bool(
            'COMPANY_AI_ENABLED',
            file_config,
            ('flags', 'company_ai_enabled'),
            True,
        ),
        'COMPANY_AI_DEFAULT_EWMA_SECONDS': _resolve_float(
            'COMPANY_AI_DEFAULT_EWMA_SECONDS',
            file_config,
            ('company_ai', 'default_ewma_seconds'),
            60,
        ),
        'RABBITMQ_URL': _env_str(
            'RABBITMQ_URL',
            'amqp://guest:guest@localhost:5672/%2F',
        ),
        'RABBITMQ_INTAKE_QUEUE': intake_queue,
        'RABBITMQ_QUEUE_NAME': _resolve_str(
            'RABBITMQ_QUEUE_NAME',
            file_config,
            ('rabbitmq', 'intake_queue'),
            intake_queue,
        ),
        'RABBITMQ_GPU_QUEUE': _resolve_str(
            'RABBITMQ_GPU_QUEUE',
            file_config,
            ('rabbitmq', 'gpu_queue'),
            'gpu_preprocessing',
        ),
        'RABBITMQ_COMPANY_QUEUE': _resolve_str(
            'RABBITMQ_COMPANY_QUEUE',
            file_config,
            ('rabbitmq', 'company_queue'),
            'company_ai_processing',
        ),
        'RABBITMQ_MAX_PRIORITY': min(
            255,
            _resolve_int(
                'RABBITMQ_MAX_PRIORITY',
                file_config,
                ('rabbitmq', 'max_priority'),
                10,
            ),
        ),
        'RABBITMQ_MAX_QUEUE_SIZE': _resolve_int(
            'RABBITMQ_MAX_QUEUE_SIZE',
            file_config,
            ('rabbitmq', 'max_queue_size'),
            19999,
        ),
        'RABBITMQ_BACKGROUND_PRIORITY': _resolve_int(
            'RABBITMQ_BACKGROUND_PRIORITY',
            file_config,
            ('rabbitmq', 'background_priority'),
            1,
        ),
        'RABBITMQ_REPORT_PRIORITY': _resolve_int(
            'RABBITMQ_REPORT_PRIORITY',
            file_config,
            ('rabbitmq', 'report_priority'),
            10,
        ),
        'COMPANY_AI_SCAN_INTERVAL_SECONDS': _resolve_int(
            'COMPANY_AI_SCAN_INTERVAL_SECONDS',
            file_config,
            ('company_ai', 'scan_interval_seconds'),
            60,
        ),
        'BACKGROUND_PREPROCESSING_ENABLED': _resolve_bool(
            'BACKGROUND_PREPROCESSING_ENABLED',
            file_config,
            ('flags', 'background_preprocessing_enabled'),
            False,
        ),
        'COMPANY_AI_STALE_PROCESSING_SECONDS': _resolve_int(
            'COMPANY_AI_STALE_PROCESSING_SECONDS',
            file_config,
            ('company_ai', 'stale_processing_seconds'),
            900,
        ),
        'COMPANY_AI_REPORT_WAIT_TIMEOUT_SECONDS': _resolve_int(
            'COMPANY_AI_REPORT_WAIT_TIMEOUT_SECONDS',
            file_config,
            ('company_ai', 'report_wait_timeout_seconds'),
            300,
        ),
        'COMPANY_AI_MAX_TASK_ATTEMPTS': _resolve_int(
            'COMPANY_AI_MAX_TASK_ATTEMPTS',
            file_config,
            ('company_ai', 'max_task_attempts'),
            10,
        ),
        'GPU_QUEUE_BACKLOG_LIMIT': _resolve_int(
            'GPU_QUEUE_BACKLOG_LIMIT',
            file_config,
            ('gpu', 'queue_backlog_limit'),
            20,
        ),
        'GPU_ENABLED': _resolve_bool(
            'GPU_ENABLED',
            file_config,
            ('flags', 'gpu_enabled'),
            False,
        ),
        'GPU_DEFAULT_EWMA_SECONDS': _resolve_float(
            'GPU_DEFAULT_EWMA_SECONDS',
            file_config,
            ('gpu', 'default_ewma_seconds'),
            30,
        ),
        'PREPROCESSING_CACHE_VERSION': _resolve_str(
            'PREPROCESSING_CACHE_VERSION',
            file_config,
            ('preprocessing', 'cache_version'),
            '1',
        ),
        'GPU_WORKER_CONCURRENCY': _resolve_int(
            'GPU_WORKER_CONCURRENCY',
            file_config,
            ('gpu', 'worker_concurrency'),
            1,
        ),
        'GPU_MAX_TASK_ATTEMPTS': _resolve_int(
            'GPU_MAX_TASK_ATTEMPTS',
            file_config,
            ('gpu', 'max_task_attempts'),
            2,
        ),
        'GPU_MODEL_PATH': _resolve_str(
            'GPU_MODEL_PATH',
            file_config,
            ('gpu', 'model_path'),
            '/models/qwen-14b-q4.gguf',
        ),
        'GPU_MODEL_NAME': _resolve_str(
            'GPU_MODEL_NAME',
            file_config,
            ('gpu', 'model_name'),
            'qwen-local',
        ),
        'GPU_CONTEXT_SIZE': _resolve_int(
            'GPU_CONTEXT_SIZE',
            file_config,
            ('gpu', 'context_size'),
            16384,
        ),
        'GPU_TENSOR_SPLIT': _resolve_str(
            'GPU_TENSOR_SPLIT',
            file_config,
            ('gpu', 'tensor_split'),
            '1,1,1',
        ),
        'GPU_INFERENCE_BASE_URL': _resolve_str(
            'GPU_INFERENCE_BASE_URL',
            file_config,
            ('gpu', 'inference_base_url'),
            'http://llama-server:8080/v1',
        ),
        'TAVILY_API_KEY': _env_str('TAVILY_API_KEY'),
        'TAVILY_SEARCH_DEPTH': _resolve_str(
            'TAVILY_SEARCH_DEPTH',
            file_config,
            ('tavily', 'search_depth'),
            'basic',
        ),
        'TAVILY_MAX_RESULTS': _resolve_int(
            'TAVILY_MAX_RESULTS',
            file_config,
            ('tavily', 'max_results'),
            5,
        ),
        'TAVILY_REQUEST_TIMEOUT_SECONDS': _resolve_int(
            'TAVILY_REQUEST_TIMEOUT_SECONDS',
            file_config,
            ('tavily', 'request_timeout_seconds'),
            30,
        ),
        'TAVILY_MAX_CONCURRENT_REQUESTS': _resolve_int(
            'TAVILY_MAX_CONCURRENT_REQUESTS',
            file_config,
            ('tavily', 'max_concurrent_requests'),
            4,
        ),
        'ENRICHED_VENDOR_DOMAIN_MAP': _resolve_dict(
            'ENRICHED_VENDOR_DOMAIN_MAP',
            file_config,
            ('enriched', 'vendor_domain_map'),
            {},
        ),
        'ENRICHED_RESULTS_PER_TASK': _resolve_int(
            'ENRICHED_RESULTS_PER_TASK',
            file_config,
            ('enriched', 'results_per_task'),
            4,
        ),
        'ENRICHED_LLM_BASE_URL': _resolve_str(
            'ENRICHED_LLM_BASE_URL',
            file_config,
            ('enriched', 'llm_base_url'),
            '',
        ),
        'ENRICHED_LLM_MODEL': _resolve_str(
            'ENRICHED_LLM_MODEL',
            file_config,
            ('enriched', 'llm_model'),
            'qwen-local',
        ),
        'ENRICHED_LLM_TIMEOUT_SECONDS': _resolve_int(
            'ENRICHED_LLM_TIMEOUT_SECONDS',
            file_config,
            ('enriched', 'llm_timeout_seconds'),
            120,
        ),
        'ENRICHED_LLM_CONNECT_TIMEOUT_SECONDS': _resolve_int(
            'ENRICHED_LLM_CONNECT_TIMEOUT_SECONDS',
            file_config,
            ('enriched', 'llm_connect_timeout_seconds'),
            30,
        ),
        'ENRICHED_LLM_MAX_OUTPUT_TOKENS': _resolve_int(
            'ENRICHED_LLM_MAX_OUTPUT_TOKENS',
            file_config,
            ('enriched', 'llm_max_output_tokens'),
            2048,
        ),
        'ENRICHED_LLM_EVIDENCE_MAX_OUTPUT_TOKENS': _resolve_int(
            'ENRICHED_LLM_EVIDENCE_MAX_OUTPUT_TOKENS',
            file_config,
            ('enriched', 'llm_evidence_max_output_tokens'),
            1024,
        ),
        'ENRICHED_LLM_REPORT_MAX_OUTPUT_TOKENS': _resolve_int(
            'ENRICHED_LLM_REPORT_MAX_OUTPUT_TOKENS',
            file_config,
            ('enriched', 'llm_report_max_output_tokens'),
            4096,
        ),
        'ENRICHED_LLM_CONNECTION_RETRIES': _resolve_int(
            'ENRICHED_LLM_CONNECTION_RETRIES',
            file_config,
            ('enriched', 'llm_connection_retries'),
            5,
        ),
        'ENRICHED_LLM_RETRY_WAIT_SECONDS': _resolve_int(
            'ENRICHED_LLM_RETRY_WAIT_SECONDS',
            file_config,
            ('enriched', 'llm_retry_wait_seconds'),
            10,
        ),
        'ENRICHED_LLM_PAGE_CHARS': _resolve_int(
            'ENRICHED_LLM_PAGE_CHARS',
            file_config,
            ('enriched', 'llm_page_chars'),
            4500,
        ),
        'ENRICHED_LLM_DISABLE_THINKING': _resolve_bool(
            'ENRICHED_LLM_DISABLE_THINKING',
            file_config,
            ('enriched', 'llm_disable_thinking'),
            True,
        ),
        'ENRICHED_EVIDENCE_CACHE_ENABLED': _resolve_bool(
            'ENRICHED_EVIDENCE_CACHE_ENABLED',
            file_config,
            ('enriched', 'evidence_cache_enabled'),
            True,
        ),
        'ENRICHED_EVIDENCE_CACHE_VERSION': _resolve_str(
            'ENRICHED_EVIDENCE_CACHE_VERSION',
            file_config,
            ('enriched', 'evidence_cache_version'),
            '1',
        ),
        'GPU_START_PROMPT': gpu_start_prompt,
        'GPU_FINAL_SUMMARY_PROMPT': gpu_final_summary_prompt,
        'REPORT_ITEM_JSON_RETRIES': _resolve_int(
            'REPORT_ITEM_JSON_RETRIES',
            file_config,
            ('report', 'item_json_retries'),
            2,
        ),
        'REPORT_FINAL_JSON_RETRIES': _resolve_int(
            'REPORT_FINAL_JSON_RETRIES',
            file_config,
            ('report', 'final_json_retries'),
            2,
        ),
        'REPORT_JSON_ERROR_MESSAGE': _resolve_str(
            'REPORT_JSON_ERROR_MESSAGE',
            file_config,
            ('report', 'json_error_message'),
            DEFAULT_JSON_ERROR_MESSAGE,
        ),
        'REPORT_DENY_KEYS': _resolve_list(
            'REPORT_DENY_KEYS',
            file_config,
            ('report', 'deny_keys'),
            ['raw', 'raw_fields', 'raw_sections', 'raw_tables'],
        ),
        'REPORT_DENY_PREFIXES': _resolve_list(
            'REPORT_DENY_PREFIXES',
            file_config,
            ('report', 'deny_prefixes'),
            ['raw_'],
        ),
        'REPORT_MAX_DEPTH': _resolve_int(
            'REPORT_MAX_DEPTH',
            file_config,
            ('report', 'max_depth'),
            6,
        ),
        'REPORT_MAX_LIST_ITEMS': _resolve_int(
            'REPORT_MAX_LIST_ITEMS',
            file_config,
            ('report', 'max_list_items'),
            100,
        ),
        'REPORT_MAX_STRING_CHARS': _resolve_int(
            'REPORT_MAX_STRING_CHARS',
            file_config,
            ('report', 'max_string_chars'),
            12000,
        ),
        'REPORT_PREVIEW_AFTER_EACH_ITEM': _resolve_bool(
            'REPORT_PREVIEW_AFTER_EACH_ITEM',
            file_config,
            ('report', 'preview_after_each_item'),
            True,
        ),
        'SCHEDULER_SCAN_INTERVAL_SECONDS': _resolve_int(
            'SCHEDULER_SCAN_INTERVAL_SECONDS',
            file_config,
            ('scheduler', 'scan_interval_seconds'),
            60,
        ),
    }

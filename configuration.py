import json
import os


DEFAULT_JSON_ERROR_MESSAGE = (
    'The JSON above is invalid.\n\nError:\n${error}\n\n'
    'Fix it and return only valid JSON. No Markdown, no explanation, no extra text. '
    'Keep the original fields and meaning. Make only the minimum changes needed so '
    'it can parse with `json.loads()`.'
)


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


def _require_env(*names):
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        raise ValueError(
            'Missing required environment variable(s): ' + ', '.join(missing),
        )


def load_application_config(base_dir, require_local=True):
    local_database = _env_str('LOCAL_DATABASE', _env_str('WEB_DATABASE', 'web'))
    newsletter_root = _env_str('NEWSLETTER_ROOT', 'newsletters')
    if not os.path.isabs(newsletter_root):
        newsletter_root = os.path.join(base_dir, newsletter_root)

    atlas_mongo_uri = _env_str('ATLAS_MONGO_URI')
    local_mongo_uri = _env_str('LOCAL_MONGO_URI')
    if require_local:
        _require_env('ATLAS_MONGO_URI', 'LOCAL_MONGO_URI', 'FLASK_SECRET_KEY')
    else:
        _require_env('ATLAS_MONGO_URI')

    legacy_queue_name = _env_str(
        'RABBITMQ_QUEUE_NAME',
        _env_str('RABBITMQ_INTAKE_QUEUE', 'company_ai_preprocessing'),
    )
    intake_queue = _env_str('RABBITMQ_INTAKE_QUEUE', legacy_queue_name)
    company_ai_start_prompt = _env_str('COMPANY_AI_START_PROMPT')
    company_ai_summary_prompt = _env_str('COMPANY_AI_SUMMARY_PROMPT')
    company_ai_username = _env_str('COMPANY_AI_USERNAME')
    gpu_start_prompt = _env_str('GPU_START_PROMPT') or company_ai_start_prompt
    gpu_final_summary_prompt = (
        _env_str('GPU_FINAL_SUMMARY_PROMPT') or company_ai_summary_prompt
    )

    return {
        'ATLAS_MONGO_URI': atlas_mongo_uri,
        'LOCAL_MONGO_URI': local_mongo_uri,
        'LOCAL_DATABASE': local_database,
        'WEB_DATABASE': _env_str('WEB_DATABASE', local_database),
        'VULNERABILITIES_DATABASE': _env_str('VULNERABILITIES_DATABASE', 'vulnerabilities'),
        'AI_TASK_COLLECTION': _env_str('AI_TASK_COLLECTION', 'ai_generation_tasks'),
        'AI_PROVIDER_METRICS_COLLECTION': _env_str(
            'AI_PROVIDER_METRICS_COLLECTION',
            'ai_provider_metrics',
        ),
        'REVIEW_VIEW_SUFFIX': _env_str('REVIEW_VIEW_SUFFIX', '_review'),
        'SECRET_KEY': _env_str('FLASK_SECRET_KEY'),
        'WEB_AUTH_BOOTSTRAP_USERNAME': _env_str('WEB_AUTH_BOOTSTRAP_USERNAME', 'admin'),
        'WEB_AUTH_BOOTSTRAP_PASSWORD': _env_str('WEB_AUTH_BOOTSTRAP_PASSWORD', 'changeme'),
        'NEWSLETTER_ROOT': newsletter_root,
        'COMPANY_AI_BASE_URL': _env_str('COMPANY_AI_BASE_URL'),
        'COMPANY_AI_USERNAME': company_ai_username,
        'COMPANY_AI_PASSWORD': _env_str('COMPANY_AI_PASSWORD'),
        'COMPANY_AI_START_PROMPT': company_ai_start_prompt,
        'COMPANY_AI_SUMMARY_PROMPT': company_ai_summary_prompt,
        'COMPANY_AI_PUBLIC_KEY_B64': _env_str('COMPANY_AI_PUBLIC_KEY_B64'),
        'COMPANY_AI_SIGN_SECRET': _env_str('COMPANY_AI_SIGN_SECRET'),
        'COMPANY_AI_API_TIMEZONE': _env_str('COMPANY_AI_API_TIMEZONE', 'Asia/Shanghai'),
        'COMPANY_AI_SSE_DELAY_SECONDS': _env_float('COMPANY_AI_SSE_DELAY_SECONDS', 2),
        'COMPANY_AI_MODEL': _env_str('COMPANY_AI_MODEL'),
        'COMPANY_AI_OWNER_ACCOUNT': _env_str('COMPANY_AI_OWNER_ACCOUNT', company_ai_username),
        'COMPANY_AI_PLATFORM_ID': _env_int('COMPANY_AI_PLATFORM_ID', 5),
        'COMPANY_AI_QA_TYPE': _env_int('COMPANY_AI_QA_TYPE', 0),
        'COMPANY_AI_FROM_SOURCE': _env_str('COMPANY_AI_FROM_SOURCE', 'normal_chat'),
        'COMPANY_AI_USE_THINK': _env_bool('COMPANY_AI_USE_THINK', True),
        'COMPANY_AI_USER_PROMPT': _env_str('COMPANY_AI_USER_PROMPT'),
        'COMPANY_AI_DATASET_IDS': _env_json_list('COMPANY_AI_DATASET_IDS', []),
        'COMPANY_AI_FILE_IDS': _env_json_list('COMPANY_AI_FILE_IDS', []),
        'COMPANY_AI_CONTEXT_LIMIT': _env_int('COMPANY_AI_CONTEXT_LIMIT', 32768),
        'COMPANY_AI_MAX_OUTPUT_TOKENS': _env_int('COMPANY_AI_MAX_OUTPUT_TOKENS', 4096),
        'COMPANY_AI_TIMEOUT_SECONDS': _env_int('COMPANY_AI_TIMEOUT_SECONDS', 180),
        'COMPANY_AI_RETRIES': _env_int('COMPANY_AI_RETRIES', 1),
        'COMPANY_AI_AUTH_TTL_SECONDS': _env_int('COMPANY_AI_AUTH_TTL_SECONDS', 3600),
        'COMPANY_AI_LOGIN_MAX_FAILURES': _env_int('COMPANY_AI_LOGIN_MAX_FAILURES', 3),
        'COMPANY_AI_PARALLEL_CHATS': _env_int('COMPANY_AI_PARALLEL_CHATS', 4),
        'COMPANY_AI_ENABLED': _env_bool('COMPANY_AI_ENABLED', True),
        'COMPANY_AI_DEFAULT_EWMA_SECONDS': _env_float('COMPANY_AI_DEFAULT_EWMA_SECONDS', 60),
        'RABBITMQ_URL': _env_str(
            'RABBITMQ_URL',
            'amqp://guest:guest@localhost:5672/%2F',
        ),
        'RABBITMQ_INTAKE_QUEUE': intake_queue,
        'RABBITMQ_QUEUE_NAME': _env_str('RABBITMQ_QUEUE_NAME', intake_queue),
        'RABBITMQ_GPU_QUEUE': _env_str('RABBITMQ_GPU_QUEUE', 'gpu_preprocessing'),
        'RABBITMQ_COMPANY_QUEUE': _env_str(
            'RABBITMQ_COMPANY_QUEUE',
            'company_ai_processing',
        ),
        'RABBITMQ_MAX_PRIORITY': min(255, _env_int('RABBITMQ_MAX_PRIORITY', 10)),
        'RABBITMQ_MAX_QUEUE_SIZE': _env_int('RABBITMQ_MAX_QUEUE_SIZE', 19999),
        'RABBITMQ_BACKGROUND_PRIORITY': _env_int('RABBITMQ_BACKGROUND_PRIORITY', 1),
        'RABBITMQ_REPORT_PRIORITY': _env_int('RABBITMQ_REPORT_PRIORITY', 10),
        'COMPANY_AI_SCAN_INTERVAL_SECONDS': _env_int('COMPANY_AI_SCAN_INTERVAL_SECONDS', 60),
        'BACKGROUND_PREPROCESSING_ENABLED': _env_bool('BACKGROUND_PREPROCESSING_ENABLED', False),
        'COMPANY_AI_STALE_PROCESSING_SECONDS': _env_int(
            'COMPANY_AI_STALE_PROCESSING_SECONDS',
            900,
        ),
        'COMPANY_AI_REPORT_WAIT_TIMEOUT_SECONDS': _env_int(
            'COMPANY_AI_REPORT_WAIT_TIMEOUT_SECONDS',
            300,
        ),
        'COMPANY_AI_MAX_TASK_ATTEMPTS': _env_int('COMPANY_AI_MAX_TASK_ATTEMPTS', 10),
        'GPU_QUEUE_BACKLOG_LIMIT': _env_int('GPU_QUEUE_BACKLOG_LIMIT', 20),
        'GPU_ENABLED': _env_bool('GPU_ENABLED', False),
        'GPU_DEFAULT_EWMA_SECONDS': _env_float('GPU_DEFAULT_EWMA_SECONDS', 30),
        'PREPROCESSING_CACHE_VERSION': _env_str('PREPROCESSING_CACHE_VERSION', '1'),
        'GPU_WORKER_CONCURRENCY': _env_int('GPU_WORKER_CONCURRENCY', 1),
        'GPU_MAX_TASK_ATTEMPTS': _env_int('GPU_MAX_TASK_ATTEMPTS', 2),
        'GPU_MODEL_PATH': _env_str('GPU_MODEL_PATH', '/models/qwen-14b-q4.gguf'),
        'GPU_MODEL_NAME': _env_str('GPU_MODEL_NAME', 'qwen-local'),
        'GPU_CONTEXT_SIZE': _env_int('GPU_CONTEXT_SIZE', 16384),
        'GPU_TENSOR_SPLIT': _env_str('GPU_TENSOR_SPLIT', '1,1,1'),
        'GPU_INFERENCE_BASE_URL': _env_str(
            'GPU_INFERENCE_BASE_URL',
            'http://llama-server:8080/v1',
        ),
        'GPU_START_PROMPT': gpu_start_prompt,
        'GPU_FINAL_SUMMARY_PROMPT': gpu_final_summary_prompt,
        'REPORT_ITEM_JSON_RETRIES': _env_int('REPORT_ITEM_JSON_RETRIES', 2),
        'REPORT_FINAL_JSON_RETRIES': _env_int('REPORT_FINAL_JSON_RETRIES', 2),
        'REPORT_JSON_ERROR_MESSAGE': _env_str(
            'REPORT_JSON_ERROR_MESSAGE',
            DEFAULT_JSON_ERROR_MESSAGE,
        ),
        'REPORT_DENY_KEYS': _env_json_list(
            'REPORT_DENY_KEYS',
            ['raw', 'raw_fields', 'raw_sections', 'raw_tables'],
        ),
        'REPORT_DENY_PREFIXES': _env_json_list('REPORT_DENY_PREFIXES', ['raw_']),
        'REPORT_MAX_DEPTH': _env_int('REPORT_MAX_DEPTH', 6),
        'REPORT_MAX_LIST_ITEMS': _env_int('REPORT_MAX_LIST_ITEMS', 100),
        'REPORT_MAX_STRING_CHARS': _env_int('REPORT_MAX_STRING_CHARS', 12000),
        'REPORT_PREVIEW_AFTER_EACH_ITEM': _env_bool('REPORT_PREVIEW_AFTER_EACH_ITEM', True),
        'SCHEDULER_SCAN_INTERVAL_SECONDS': _env_int('SCHEDULER_SCAN_INTERVAL_SECONDS', 60),
    }

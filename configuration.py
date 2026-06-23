import json
import os

from enriched_report.prompts import DEFAULT_PROMPTS, merge_prompts


DEFAULT_JSON_ERROR_MESSAGE = DEFAULT_PROMPTS['json_error_message']

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


def _resolve_key_list(list_env, single_env, file_config, json_keys):
    keys = _resolve_list(list_env, file_config, json_keys, [])
    if not keys and _env_set(single_env):
        keys = [_env_str(single_env)]
    return [str(key).strip() for key in keys if str(key).strip()]


def _resolve_prompts(file_config):
    return merge_prompts(_dig(file_config, 'prompts'))


def load_application_config(base_dir):
    file_config = _load_file_config(base_dir)
    ai_prompts = _resolve_prompts(file_config)
    json_error_message = _resolve_str(
        'REPORT_JSON_ERROR_MESSAGE',
        file_config,
        ('prompts', 'json_error_message'),
        DEFAULT_PROMPTS['json_error_message'],
    )
    ai_prompts = {**ai_prompts, 'json_error_message': json_error_message}

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
    _require_env('ATLAS_MONGO_URI', 'LOCAL_MONGO_URI', 'FLASK_SECRET_KEY')

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
        'TAVILY_API_KEYS': _resolve_key_list(
            'TAVILY_API_KEYS',
            'TAVILY_API_KEY',
            file_config,
            ('tavily', 'api_keys'),
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
        'EXA_API_KEYS': _resolve_key_list(
            'EXA_API_KEYS',
            'EXA_API_KEY',
            file_config,
            ('exa', 'api_keys'),
        ),
        'EXA_SEARCH_TYPE': _resolve_str(
            'EXA_SEARCH_TYPE',
            file_config,
            ('exa', 'type'),
            'auto',
        ),
        'EXA_MAX_RESULTS': _resolve_int(
            'EXA_MAX_RESULTS',
            file_config,
            ('exa', 'max_results'),
            5,
        ),
        'EXA_REQUEST_TIMEOUT_SECONDS': _resolve_int(
            'EXA_REQUEST_TIMEOUT_SECONDS',
            file_config,
            ('exa', 'request_timeout_seconds'),
            30,
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
        'REPORT_JSON_ERROR_MESSAGE': json_error_message,
        'AI_PROMPTS': ai_prompts,
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
    }

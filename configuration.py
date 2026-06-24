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


def _require_env(*names):
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        raise ValueError(
            'Missing required environment variable(s): ' + ', '.join(missing),
        )


def _bool(value):
    return str(value).lower() in {'1', 'true', 'yes', 'on'}


def _list(value, default):
    if value is None or value == '':
        return list(default)
    if isinstance(value, list):
        return list(value)
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return parsed
    except (TypeError, json.JSONDecodeError):
        pass
    return [item.strip() for item in str(value).split(',') if item.strip()]


def _dict(value, default):
    if value is None or value == '':
        return dict(default)
    if isinstance(value, dict):
        return dict(value)
    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    except (TypeError, json.JSONDecodeError):
        pass
    return dict(default)


def _resolve(env_name, file_config, json_keys, default='', cast=str):
    value = os.environ.get(env_name)
    if value in (None, ''):
        value = _dig(file_config, *json_keys) if json_keys else None
    if value in (None, ''):
        value = default
    if cast is list:
        return _list(value, default)
    if cast is dict:
        return _dict(value, default)
    if cast is bool:
        return _bool(value)
    return cast(value)


def _resolve_key_list(list_env, single_env, file_config, json_keys):
    keys = _resolve(list_env, file_config, json_keys, [], list)
    single_value = os.environ.get(single_env)
    if not keys and single_value:
        keys = [single_value]
    return [str(key).strip() for key in keys if str(key).strip()]


def _resolve_prompts(file_config):
    return merge_prompts(_dig(file_config, 'prompts'))


def load_application_config(base_dir):
    file_config = _load_file_config(base_dir)
    ai_prompts = _resolve_prompts(file_config)
    json_error_message = _resolve(
        'REPORT_JSON_ERROR_MESSAGE',
        file_config,
        ('prompts', 'json_error_message'),
        DEFAULT_PROMPTS['json_error_message'],
    )
    ai_prompts = {**ai_prompts, 'json_error_message': json_error_message}

    local_database = _resolve(
        'LOCAL_DATABASE',
        file_config,
        ('mongodb', 'local_database'),
        _resolve('WEB_DATABASE', file_config, ('mongodb', 'web_database'), 'web'),
    )
    newsletter_root = _resolve('NEWSLETTER_ROOT', file_config, ('newsletter_root',), 'newsletters')
    if not os.path.isabs(newsletter_root):
        newsletter_root = os.path.join(base_dir, newsletter_root)

    mongo_uri = os.environ.get('MONGO_URI') or os.environ.get('LOCAL_MONGO_URI', '')
    if not mongo_uri:
        _require_env('LOCAL_MONGO_URI', 'FLASK_SECRET_KEY')
    else:
        _require_env('FLASK_SECRET_KEY')

    return {
        'MONGO_URI': mongo_uri,
        'LOCAL_MONGO_URI': mongo_uri,
        'LOCAL_DATABASE': local_database,
        'WEB_DATABASE': _resolve(
            'WEB_DATABASE',
            file_config,
            ('mongodb', 'web_database'),
            local_database,
        ),
        'VULNERABILITIES_DATABASE': _resolve(
            'VULNERABILITIES_DATABASE',
            file_config,
            ('mongodb', 'vulnerabilities_database'),
            'vulnerabilities',
        ),
        'REVIEW_VIEW_SUFFIX': _resolve(
            'REVIEW_VIEW_SUFFIX',
            file_config,
            ('mongodb', 'review_view_suffix'),
            '_review',
        ),
        'SECRET_KEY': os.environ.get('FLASK_SECRET_KEY', ''),
        'WEB_AUTH_BOOTSTRAP_USERNAME': _resolve(
            'WEB_AUTH_BOOTSTRAP_USERNAME',
            file_config,
            ('web_auth', 'bootstrap_username'),
            'admin',
        ),
        'WEB_AUTH_BOOTSTRAP_PASSWORD': os.environ.get('WEB_AUTH_BOOTSTRAP_PASSWORD', 'changeme'),
        'NEWSLETTER_ROOT': newsletter_root,
        'TAVILY_API_KEYS': _resolve_key_list(
            'TAVILY_API_KEYS',
            'TAVILY_API_KEY',
            file_config,
            ('tavily', 'api_keys'),
        ),
        'TAVILY_API_KEY': os.environ.get('TAVILY_API_KEY', ''),
        'TAVILY_SEARCH_DEPTH': _resolve(
            'TAVILY_SEARCH_DEPTH',
            file_config,
            ('tavily', 'search_depth'),
            'basic',
        ),
        'TAVILY_MAX_RESULTS': _resolve(
            'TAVILY_MAX_RESULTS',
            file_config,
            ('tavily', 'max_results'),
            5,
            int,
        ),
        'TAVILY_REQUEST_TIMEOUT_SECONDS': _resolve(
            'TAVILY_REQUEST_TIMEOUT_SECONDS',
            file_config,
            ('tavily', 'request_timeout_seconds'),
            30,
            int,
        ),
        'TAVILY_MAX_CONCURRENT_REQUESTS': _resolve(
            'TAVILY_MAX_CONCURRENT_REQUESTS',
            file_config,
            ('tavily', 'max_concurrent_requests'),
            4,
            int,
        ),
        'SEARCH_PROVIDER_ORDER': _resolve(
            'SEARCH_PROVIDER_ORDER',
            file_config,
            ('search', 'provider_order'),
            ['tavily', 'exa', 'searxng'],
            list,
        ),
        'EXA_API_KEYS': _resolve_key_list(
            'EXA_API_KEYS',
            'EXA_API_KEY',
            file_config,
            ('exa', 'api_keys'),
        ),
        'EXA_SEARCH_TYPE': _resolve(
            'EXA_SEARCH_TYPE',
            file_config,
            ('exa', 'type'),
            'auto',
        ),
        'EXA_MAX_RESULTS': _resolve(
            'EXA_MAX_RESULTS',
            file_config,
            ('exa', 'max_results'),
            5,
            int,
        ),
        'EXA_REQUEST_TIMEOUT_SECONDS': _resolve(
            'EXA_REQUEST_TIMEOUT_SECONDS',
            file_config,
            ('exa', 'request_timeout_seconds'),
            30,
            int,
        ),
        'SEARXNG_BASE_URL': _resolve(
            'SEARXNG_BASE_URL',
            file_config,
            ('searxng', 'base_url'),
            '',
        ),
        'SEARXNG_MAX_RESULTS': _resolve(
            'SEARXNG_MAX_RESULTS',
            file_config,
            ('searxng', 'max_results'),
            _resolve('TAVILY_MAX_RESULTS', file_config, ('tavily', 'max_results'), 5, int),
            int,
        ),
        'SEARXNG_REQUEST_TIMEOUT_SECONDS': _resolve(
            'SEARXNG_REQUEST_TIMEOUT_SECONDS',
            file_config,
            ('searxng', 'request_timeout_seconds'),
            _resolve('TAVILY_REQUEST_TIMEOUT_SECONDS', file_config, ('tavily', 'request_timeout_seconds'), 30, int),
            int,
        ),
        'SEARXNG_FETCH_TIMEOUT_SECONDS': _resolve(
            'SEARXNG_FETCH_TIMEOUT_SECONDS',
            file_config,
            ('searxng', 'fetch_timeout_seconds'),
            _resolve('TAVILY_REQUEST_TIMEOUT_SECONDS', file_config, ('tavily', 'request_timeout_seconds'), 30, int),
            int,
        ),
        'SEARXNG_MAX_SNIPPET_CHARS': _resolve(
            'SEARXNG_MAX_SNIPPET_CHARS',
            file_config,
            ('searxng', 'max_snippet_chars'),
            8192,
            int,
        ),
        'SEARXNG_COMPRESSION_CHUNK_CHARS': _resolve(
            'SEARXNG_COMPRESSION_CHUNK_CHARS',
            file_config,
            ('searxng', 'compression_chunk_chars'),
            _resolve('ENRICHED_LLM_PAGE_CHARS', file_config, ('enriched', 'llm_page_chars'), 12000, int),
            int,
        ),
        'SEARXNG_COMPRESSION_FAN_IN': _resolve(
            'SEARXNG_COMPRESSION_FAN_IN',
            file_config,
            ('searxng', 'compression_fan_in'),
            _resolve('REPORT_SECTION_CHUNK_CARD_COUNT', file_config, ('report', 'section_chunk_card_count'), 4, int),
            int,
        ),
        'ENRICHED_VENDOR_DOMAIN_MAP': _resolve(
            'ENRICHED_VENDOR_DOMAIN_MAP',
            file_config,
            ('enriched', 'vendor_domain_map'),
            {},
            dict,
        ),
        'ENRICHED_RESULTS_PER_TASK': _resolve(
            'ENRICHED_RESULTS_PER_TASK',
            file_config,
            ('enriched', 'results_per_task'),
            4,
            int,
        ),
        'ENRICHED_LLM_BASE_URL': _resolve(
            'ENRICHED_LLM_BASE_URL',
            file_config,
            ('enriched', 'llm_base_url'),
            '',
        ),
        'ENRICHED_LLM_MODEL': _resolve(
            'ENRICHED_LLM_MODEL',
            file_config,
            ('enriched', 'llm_model'),
            'qwen-local',
        ),
        'ENRICHED_LLM_TIMEOUT_SECONDS': _resolve(
            'ENRICHED_LLM_TIMEOUT_SECONDS',
            file_config,
            ('enriched', 'llm_timeout_seconds'),
            120,
            int,
        ),
        'ENRICHED_LLM_CONNECT_TIMEOUT_SECONDS': _resolve(
            'ENRICHED_LLM_CONNECT_TIMEOUT_SECONDS',
            file_config,
            ('enriched', 'llm_connect_timeout_seconds'),
            30,
            int,
        ),
        'ENRICHED_LLM_MAX_OUTPUT_TOKENS': _resolve(
            'ENRICHED_LLM_MAX_OUTPUT_TOKENS',
            file_config,
            ('enriched', 'llm_max_output_tokens'),
            2048,
            int,
        ),
        'ENRICHED_LLM_EVIDENCE_MAX_OUTPUT_TOKENS': _resolve(
            'ENRICHED_LLM_EVIDENCE_MAX_OUTPUT_TOKENS',
            file_config,
            ('enriched', 'llm_evidence_max_output_tokens'),
            1024,
            int,
        ),
        'ENRICHED_LLM_REPORT_MAX_OUTPUT_TOKENS': _resolve(
            'ENRICHED_LLM_REPORT_MAX_OUTPUT_TOKENS',
            file_config,
            ('enriched', 'llm_report_max_output_tokens'),
            4096,
            int,
        ),
        'ENRICHED_LLM_CONNECTION_RETRIES': _resolve(
            'ENRICHED_LLM_CONNECTION_RETRIES',
            file_config,
            ('enriched', 'llm_connection_retries'),
            5,
            int,
        ),
        'ENRICHED_LLM_RETRY_WAIT_SECONDS': _resolve(
            'ENRICHED_LLM_RETRY_WAIT_SECONDS',
            file_config,
            ('enriched', 'llm_retry_wait_seconds'),
            10,
            int,
        ),
        'ENRICHED_LLM_PAGE_CHARS': _resolve(
            'ENRICHED_LLM_PAGE_CHARS',
            file_config,
            ('enriched', 'llm_page_chars'),
            4500,
            int,
        ),
        'ENRICHED_LLM_DISABLE_THINKING': _resolve(
            'ENRICHED_LLM_DISABLE_THINKING',
            file_config,
            ('enriched', 'llm_disable_thinking'),
            True,
            bool,
        ),
        'ENRICHED_EVIDENCE_CACHE_ENABLED': _resolve(
            'ENRICHED_EVIDENCE_CACHE_ENABLED',
            file_config,
            ('enriched', 'evidence_cache_enabled'),
            True,
            bool,
        ),
        'ENRICHED_EVIDENCE_CACHE_VERSION': _resolve(
            'ENRICHED_EVIDENCE_CACHE_VERSION',
            file_config,
            ('enriched', 'evidence_cache_version'),
            '1',
        ),
        'REPORT_SECTION_CHUNK_PROMPT_CHARS': _resolve(
            'REPORT_SECTION_CHUNK_PROMPT_CHARS',
            file_config,
            ('report', 'section_chunk_prompt_chars'),
            20000,
            int,
        ),
        'REPORT_SECTION_CHUNK_CARD_COUNT': _resolve(
            'REPORT_SECTION_CHUNK_CARD_COUNT',
            file_config,
            ('report', 'section_chunk_card_count'),
            4,
            int,
        ),
        'REPORT_ITEM_JSON_RETRIES': _resolve(
            'REPORT_ITEM_JSON_RETRIES',
            file_config,
            ('report', 'item_json_retries'),
            2,
            int,
        ),
        'REPORT_FINAL_JSON_RETRIES': _resolve(
            'REPORT_FINAL_JSON_RETRIES',
            file_config,
            ('report', 'final_json_retries'),
            2,
            int,
        ),
        'REPORT_JSON_ERROR_MESSAGE': json_error_message,
        'AI_PROMPTS': ai_prompts,
        'REPORT_DENY_KEYS': _resolve(
            'REPORT_DENY_KEYS',
            file_config,
            ('report', 'deny_keys'),
            ['raw', 'raw_fields', 'raw_sections', 'raw_tables'],
            list,
        ),
        'REPORT_DENY_PREFIXES': _resolve(
            'REPORT_DENY_PREFIXES',
            file_config,
            ('report', 'deny_prefixes'),
            ['raw_'],
            list,
        ),
        'REPORT_MAX_DEPTH': _resolve(
            'REPORT_MAX_DEPTH',
            file_config,
            ('report', 'max_depth'),
            6,
            int,
        ),
        'REPORT_MAX_LIST_ITEMS': _resolve(
            'REPORT_MAX_LIST_ITEMS',
            file_config,
            ('report', 'max_list_items'),
            100,
            int,
        ),
        'REPORT_MAX_STRING_CHARS': _resolve(
            'REPORT_MAX_STRING_CHARS',
            file_config,
            ('report', 'max_string_chars'),
            12000,
            int,
        ),
        'REPORT_PREVIEW_AFTER_EACH_ITEM': _resolve(
            'REPORT_PREVIEW_AFTER_EACH_ITEM',
            file_config,
            ('report', 'preview_after_each_item'),
            True,
            bool,
        ),
    }

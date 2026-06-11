import json
import os


def load_application_config(base_dir):
    config_path = os.environ.get(
        'APP_CONFIG',
        os.path.join(base_dir, 'config', 'config.json'),
    )

    with open(config_path, 'r', encoding='utf-8') as config_file:
        file_config = json.load(config_file)

    company_ai_config = file_config.get('company_ai', {})
    rabbitmq_config = file_config.get('rabbitmq', {})
    preprocessing_config = file_config.get('company_ai_preprocessing', {})
    report_config = file_config.get('report_processing', {})
    newsletter_root = file_config.get('newsletter_root', 'newsletters')
    sources_config = file_config.get('sources_config', os.path.join('config', 'sources.json'))
    if not os.path.isabs(newsletter_root):
        newsletter_root = os.path.join(base_dir, newsletter_root)
    if not os.path.isabs(sources_config):
        sources_config = os.path.join(base_dir, sources_config)

    return {
        'MONGO_URI': os.environ.get('MONGO_URI', file_config['mongo_uri']),
        'WEB_DATABASE': os.environ.get(
            'WEB_DATABASE',
            file_config['web_database'],
        ),
        'VULNERABILITIES_DATABASE': os.environ.get(
            'VULNERABILITIES_DATABASE',
            file_config['vulnerabilities_database'],
        ),
        'REVIEW_VIEW_SUFFIX': os.environ.get(
            'REVIEW_VIEW_SUFFIX',
            file_config.get('review_view_suffix', '_review'),
        ),
        'SECRET_KEY': os.environ.get(
            'FLASK_SECRET_KEY',
            file_config['flask_secret_key'],
        ),
        'NEWSLETTER_ROOT': os.environ.get(
            'NEWSLETTER_ROOT',
            newsletter_root,
        ),
        'SOURCES_CONFIG': os.environ.get(
            'SOURCES_CONFIG',
            sources_config,
        ),
        'COMPANY_AI_BASE_URL': os.environ.get(
            'COMPANY_AI_BASE_URL',
            company_ai_config.get('base_url', ''),
        ),
        'COMPANY_AI_USERNAME': os.environ.get(
            'COMPANY_AI_USERNAME',
            company_ai_config.get('username', ''),
        ),
        'COMPANY_AI_PASSWORD': os.environ.get(
            'COMPANY_AI_PASSWORD',
            company_ai_config.get('password', ''),
        ),
        'COMPANY_AI_START_PROMPT': company_ai_config.get('start_prompt', ''),
        'COMPANY_AI_SUMMARY_PROMPT': os.environ.get(
            'COMPANY_AI_SUMMARY_PROMPT',
            company_ai_config.get('summary_prompt', ''),
        ),
        'COMPANY_AI_PUBLIC_KEY_B64': company_ai_config.get('public_key_b64', ''),
        'COMPANY_AI_SIGN_SECRET': company_ai_config.get('sign_secret', ''),
        'COMPANY_AI_API_TIMEZONE': company_ai_config.get('api_timezone', 'Asia/Shanghai'),
        'COMPANY_AI_SSE_DELAY_SECONDS': float(
            company_ai_config.get('sse_connection_delay_seconds', 2),
        ),
        'COMPANY_AI_MODEL': os.environ.get(
            'COMPANY_AI_MODEL',
            company_ai_config.get('model', ''),
        ),
        'COMPANY_AI_OWNER_ACCOUNT': os.environ.get(
            'COMPANY_AI_OWNER_ACCOUNT',
            company_ai_config.get('owner_account', company_ai_config.get('username', '')),
        ),
        'COMPANY_AI_PLATFORM_ID': int(os.environ.get(
            'COMPANY_AI_PLATFORM_ID',
            company_ai_config.get('platform_id', 5),
        )),
        'COMPANY_AI_QA_TYPE': int(os.environ.get(
            'COMPANY_AI_QA_TYPE',
            company_ai_config.get('qa_type', 0),
        )),
        'COMPANY_AI_FROM_SOURCE': os.environ.get(
            'COMPANY_AI_FROM_SOURCE',
            company_ai_config.get('from_source', 'normal_chat'),
        ),
        'COMPANY_AI_USE_THINK': str(os.environ.get(
            'COMPANY_AI_USE_THINK',
            company_ai_config.get('use_think', True),
        )).lower() in {'1', 'true', 'yes', 'on'},
        'COMPANY_AI_USER_PROMPT': os.environ.get(
            'COMPANY_AI_USER_PROMPT',
            company_ai_config.get('user_prompt', ''),
        ),
        'COMPANY_AI_DATASET_IDS': company_ai_config.get('dataset_ids', []),
        'COMPANY_AI_FILE_IDS': company_ai_config.get('file_ids', []),
        'COMPANY_AI_CONTEXT_LIMIT': int(os.environ.get(
            'COMPANY_AI_CONTEXT_LIMIT',
            company_ai_config.get('context_limit', 32768),
        )),
        'COMPANY_AI_MAX_OUTPUT_TOKENS': int(os.environ.get(
            'COMPANY_AI_MAX_OUTPUT_TOKENS',
            company_ai_config.get('max_output_tokens', 4096),
        )),
        'COMPANY_AI_TIMEOUT_SECONDS': int(os.environ.get(
            'COMPANY_AI_TIMEOUT_SECONDS',
            company_ai_config.get('timeout_seconds', 180),
        )),
        'COMPANY_AI_RETRIES': int(os.environ.get(
            'COMPANY_AI_RETRIES',
            company_ai_config.get('retries', 1),
        )),
        'COMPANY_AI_PARALLEL_CHATS': int(os.environ.get(
            'COMPANY_AI_PARALLEL_CHATS',
            company_ai_config.get('parallel_chats', 4),
        )),
        'RABBITMQ_URL': os.environ.get(
            'RABBITMQ_URL',
            rabbitmq_config.get('url', 'amqp://guest:guest@localhost:5672/%2F'),
        ),
        'RABBITMQ_QUEUE_NAME': os.environ.get(
            'RABBITMQ_QUEUE_NAME',
            rabbitmq_config.get('queue_name', 'company_ai_preprocessing'),
        ),
        'RABBITMQ_MAX_PRIORITY': min(255, int(os.environ.get(
            'RABBITMQ_MAX_PRIORITY',
            rabbitmq_config.get('max_priority', 10),
        ))),
        'RABBITMQ_BACKGROUND_PRIORITY': int(os.environ.get(
            'RABBITMQ_BACKGROUND_PRIORITY',
            rabbitmq_config.get('background_priority', 1),
        )),
        'RABBITMQ_REPORT_PRIORITY': int(os.environ.get(
            'RABBITMQ_REPORT_PRIORITY',
            rabbitmq_config.get('report_priority', 10),
        )),
        'COMPANY_AI_SCAN_INTERVAL_SECONDS': int(os.environ.get(
            'COMPANY_AI_SCAN_INTERVAL_SECONDS',
            preprocessing_config.get('scan_interval_seconds', 60),
        )),
        'COMPANY_AI_STALE_PROCESSING_SECONDS': int(os.environ.get(
            'COMPANY_AI_STALE_PROCESSING_SECONDS',
            preprocessing_config.get('stale_processing_seconds', 900),
        )),
        'COMPANY_AI_REPORT_WAIT_TIMEOUT_SECONDS': int(os.environ.get(
            'COMPANY_AI_REPORT_WAIT_TIMEOUT_SECONDS',
            preprocessing_config.get('report_wait_timeout_seconds', 300),
        )),
        'REPORT_ITEM_JSON_RETRIES': int(report_config.get('item_json_retries', 2)),
        'REPORT_FINAL_JSON_RETRIES': int(report_config.get('final_json_retries', 2)),
        'REPORT_JSON_ERROR_MESSAGE': os.environ.get(
            'REPORT_JSON_ERROR_MESSAGE',
            report_config.get(
                'json_error_message',
                'The JSON above is invalid.\n\nError:\n${error}\n\n'
                'Fix it and return only valid JSON. No Markdown, no explanation, no extra text. '
                'Keep the original fields and meaning. Make only the minimum changes needed so '
                'it can parse with `json.loads()`.',
            ),
        ),
        'REPORT_DENY_KEYS': report_config.get(
            'deny_keys',
            ['raw', 'raw_fields', 'raw_sections', 'raw_tables'],
        ),
        'REPORT_DENY_PREFIXES': report_config.get('deny_prefixes', ['raw_']),
        'REPORT_MAX_DEPTH': int(report_config.get('max_depth', 6)),
        'REPORT_MAX_LIST_ITEMS': int(report_config.get('max_list_items', 100)),
        'REPORT_MAX_STRING_CHARS': int(report_config.get('max_string_chars', 12000)),
        'REPORT_PREVIEW_AFTER_EACH_ITEM': bool(report_config.get('preview_after_each_item', True)),
    }

import json

import pytest

from configuration import load_application_config


def test_settings_load_from_single_json_config(tmp_path, monkeypatch):
    config_dir = tmp_path / 'config'
    config_dir.mkdir()
    config = {
        'mongo_uri': 'mongodb://example/',
        'web_database': 'web',
        'vulnerabilities_database': 'vulnerabilities',
        'review_view_suffix': '_review',
        'flask_secret_key': 'secret',
        'company_ai': {
            'base_url': 'https://company.example',
            'username': 'owner',
            'password': 'password',
            'start_prompt': 'initial',
            'summary_prompt': 'Summary in ${language}.',
            'public_key_b64': 'public-key',
            'sign_secret': 'sign-secret',
            'api_timezone': 'Asia/Shanghai',
            'sse_connection_delay_seconds': 1.5,
            'model': 'company-model',
            'owner_account': 'owner',
            'platform_id': 6,
            'qa_type': 1,
            'from_source': 'report',
            'use_think': False,
            'user_prompt': 'prompt',
            'dataset_ids': ['dataset'],
            'file_ids': ['file'],
            'context_limit': 22000,
            'max_output_tokens': 2200,
            'timeout_seconds': 90,
            'retries': 3,
            'parallel_chats': 6,
        },
        'rabbitmq': {
            'url': 'amqp://rabbit.example/',
            'queue_name': 'summaries',
            'max_priority': 8,
            'background_priority': 2,
            'report_priority': 8,
        },
        'company_ai_preprocessing': {
            'scan_interval_seconds': 30,
            'stale_processing_seconds': 600,
            'report_wait_timeout_seconds': 45,
        },
        'report_processing': {
            'item_json_retries': 4,
            'final_json_retries': 5,
            'json_error_message': 'Configured JSON error: ${error}',
            'deny_keys': ['raw'],
            'deny_prefixes': ['raw_'],
            'max_depth': 7,
            'max_list_items': 8,
            'max_string_chars': 900,
            'preview_after_each_item': False,
        },
    }
    (config_dir / 'config.json').write_text(json.dumps(config), encoding='utf-8')

    loaded = load_application_config(str(tmp_path))
    assert loaded['ATLAS_MONGO_URI'] == 'mongodb://example/'
    assert loaded['LOCAL_MONGO_URI'] == 'mongodb://example/'
    assert loaded['LOCAL_DATABASE'] == 'web'
    assert loaded['COMPANY_AI_BASE_URL'] == 'https://company.example'
    assert loaded['COMPANY_AI_USERNAME'] == 'owner'
    assert loaded['COMPANY_AI_PASSWORD'] == 'password'
    assert loaded['COMPANY_AI_START_PROMPT'] == 'initial'
    assert loaded['COMPANY_AI_SUMMARY_PROMPT'] == 'Summary in ${language}.'
    assert loaded['COMPANY_AI_PUBLIC_KEY_B64'] == 'public-key'
    assert loaded['COMPANY_AI_SIGN_SECRET'] == 'sign-secret'
    assert loaded['COMPANY_AI_SSE_DELAY_SECONDS'] == 1.5
    assert loaded['COMPANY_AI_MODEL'] == 'company-model'
    assert loaded['COMPANY_AI_OWNER_ACCOUNT'] == 'owner'
    assert loaded['COMPANY_AI_PLATFORM_ID'] == 6
    assert loaded['COMPANY_AI_QA_TYPE'] == 1
    assert loaded['COMPANY_AI_FROM_SOURCE'] == 'report'
    assert loaded['COMPANY_AI_USE_THINK'] is False
    assert loaded['COMPANY_AI_USER_PROMPT'] == 'prompt'
    assert loaded['COMPANY_AI_DATASET_IDS'] == ['dataset']
    assert loaded['COMPANY_AI_FILE_IDS'] == ['file']
    assert loaded['COMPANY_AI_CONTEXT_LIMIT'] == 22000
    assert loaded['COMPANY_AI_MAX_OUTPUT_TOKENS'] == 2200
    assert loaded['COMPANY_AI_TIMEOUT_SECONDS'] == 90
    assert loaded['COMPANY_AI_RETRIES'] == 3
    assert loaded['COMPANY_AI_AUTH_TTL_SECONDS'] == 3600
    assert loaded['COMPANY_AI_LOGIN_MAX_FAILURES'] == 3
    assert loaded['COMPANY_AI_PARALLEL_CHATS'] == 6
    assert loaded['COMPANY_AI_ENABLED'] is True
    assert loaded['RABBITMQ_URL'] == 'amqp://rabbit.example/'
    assert loaded['RABBITMQ_QUEUE_NAME'] == 'summaries'
    assert loaded['RABBITMQ_INTAKE_QUEUE'] == 'summaries'
    assert loaded['RABBITMQ_GPU_QUEUE'] == 'gpu_preprocessing'
    assert loaded['RABBITMQ_COMPANY_QUEUE'] == 'company_ai_processing'
    assert loaded['RABBITMQ_MAX_PRIORITY'] == 8
    assert loaded['RABBITMQ_BACKGROUND_PRIORITY'] == 2
    assert loaded['RABBITMQ_REPORT_PRIORITY'] == 8
    assert loaded['COMPANY_AI_SCAN_INTERVAL_SECONDS'] == 30
    assert loaded['COMPANY_AI_STALE_PROCESSING_SECONDS'] == 600
    assert loaded['COMPANY_AI_REPORT_WAIT_TIMEOUT_SECONDS'] == 45
    assert loaded['GPU_QUEUE_BACKLOG_LIMIT'] == 20
    assert loaded['GPU_ENABLED'] is False
    assert loaded['GPU_START_PROMPT'] == 'initial'
    assert loaded['PREPROCESSING_CACHE_VERSION'] == '1'
    assert loaded['REPORT_ITEM_JSON_RETRIES'] == 4
    assert loaded['REPORT_FINAL_JSON_RETRIES'] == 5
    assert loaded['REPORT_JSON_ERROR_MESSAGE'] == 'Configured JSON error: ${error}'
    assert loaded['REPORT_DENY_KEYS'] == ['raw']
    assert loaded['REPORT_PREVIEW_AFTER_EACH_ITEM'] is False

    monkeypatch.setenv('COMPANY_AI_USE_THINK', 'true')
    monkeypatch.setenv('COMPANY_AI_TIMEOUT_SECONDS', '120')
    monkeypatch.setenv('COMPANY_AI_USERNAME', 'environment-user')
    monkeypatch.setenv('COMPANY_AI_PASSWORD', 'environment-password')
    monkeypatch.setenv('COMPANY_AI_PARALLEL_CHATS', '9')
    monkeypatch.setenv('RABBITMQ_REPORT_PRIORITY', '7')
    monkeypatch.setenv('REPORT_JSON_ERROR_MESSAGE', 'Environment JSON error: ${error}')
    overridden = load_application_config(str(tmp_path))
    assert overridden['COMPANY_AI_USE_THINK'] is True
    assert overridden['COMPANY_AI_TIMEOUT_SECONDS'] == 120
    assert overridden['COMPANY_AI_USERNAME'] == 'environment-user'
    assert overridden['COMPANY_AI_PASSWORD'] == 'environment-password'
    assert overridden['COMPANY_AI_PARALLEL_CHATS'] == 9
    assert overridden['RABBITMQ_REPORT_PRIORITY'] == 7
    assert overridden['REPORT_JSON_ERROR_MESSAGE'] == 'Environment JSON error: ${error}'

    monkeypatch.delenv('RABBITMQ_INTAKE_QUEUE', raising=False)
    monkeypatch.setenv('RABBITMQ_QUEUE_NAME', 'legacy-environment-intake')
    legacy_queue = load_application_config(str(tmp_path))
    assert legacy_queue['RABBITMQ_INTAKE_QUEUE'] == 'legacy-environment-intake'


def test_separate_mongo_connections_override_legacy_uri(tmp_path, monkeypatch):
    config_dir = tmp_path / 'config'
    config_dir.mkdir()
    (config_dir / 'config.json').write_text(json.dumps({
        'atlas_mongo_uri': 'mongodb+srv://atlas.example/',
        'local_mongo_uri': 'mongodb://local.example/',
        'local_database': 'local_app',
        'vulnerabilities_database': 'vulnerabilities',
        'flask_secret_key': 'secret',
    }), encoding='utf-8')

    loaded = load_application_config(str(tmp_path))
    assert loaded['ATLAS_MONGO_URI'] == 'mongodb+srv://atlas.example/'
    assert loaded['LOCAL_MONGO_URI'] == 'mongodb://local.example/'
    assert loaded['LOCAL_DATABASE'] == 'local_app'

    monkeypatch.setenv('LOCAL_MONGO_URI', 'mongodb://environment-local/')
    assert load_application_config(str(tmp_path))['LOCAL_MONGO_URI'] == (
        'mongodb://environment-local/'
    )


def test_mongo_connections_are_required(tmp_path):
    config_dir = tmp_path / 'config'
    config_dir.mkdir()
    (config_dir / 'config.json').write_text(json.dumps({
        'vulnerabilities_database': 'vulnerabilities',
        'flask_secret_key': 'secret',
    }), encoding='utf-8')

    with pytest.raises(ValueError, match='atlas_mongo_uri and local_mongo_uri'):
        load_application_config(str(tmp_path))


def test_worker_configuration_requires_atlas_but_not_local_mongo(tmp_path):
    config_dir = tmp_path / 'config'
    config_dir.mkdir()
    (config_dir / 'config.json').write_text(json.dumps({
        'atlas_mongo_uri': 'mongodb://atlas.example/',
        'vulnerabilities_database': 'vulnerabilities',
        'flask_secret_key': 'secret',
    }), encoding='utf-8')

    loaded = load_application_config(str(tmp_path), require_local=False)
    assert loaded['ATLAS_MONGO_URI'] == 'mongodb://atlas.example/'
    assert loaded['LOCAL_MONGO_URI'] == ''
    assert loaded['AI_TASK_COLLECTION'] == 'ai_generation_tasks'


def test_file_only_settings_can_be_overridden_by_environment(tmp_path, monkeypatch):
    config_dir = tmp_path / 'config'
    config_dir.mkdir()
    (config_dir / 'config.json').write_text(
        json.dumps({
            'mongo_uri': 'mongodb://example/',
            'web_database': 'web',
            'vulnerabilities_database': 'vulnerabilities',
            'flask_secret_key': 'secret',
            'company_ai': {
                'start_prompt': 'from-file',
                'public_key_b64': 'file-key',
                'sign_secret': 'file-secret',
                'api_timezone': 'Asia/Shanghai',
                'sse_connection_delay_seconds': 2,
                'dataset_ids': ['file-dataset'],
                'file_ids': ['file-id'],
            },
            'company_ai_preprocessing': {
                'max_task_attempts': 10,
            },
            'report_processing': {
                'item_json_retries': 2,
                'final_json_retries': 2,
                'deny_keys': ['raw'],
                'deny_prefixes': ['raw_'],
                'max_depth': 6,
                'max_list_items': 100,
                'max_string_chars': 12000,
                'preview_after_each_item': True,
            },
        }),
        encoding='utf-8',
    )

    monkeypatch.setenv('COMPANY_AI_START_PROMPT', 'from-env')
    monkeypatch.setenv('COMPANY_AI_PUBLIC_KEY_B64', 'env-key')
    monkeypatch.setenv('COMPANY_AI_SIGN_SECRET', 'env-secret')
    monkeypatch.setenv('COMPANY_AI_API_TIMEZONE', 'UTC')
    monkeypatch.setenv('COMPANY_AI_SSE_DELAY_SECONDS', '3.5')
    monkeypatch.setenv('COMPANY_AI_DATASET_IDS', '["env-dataset"]')
    monkeypatch.setenv('COMPANY_AI_FILE_IDS', 'env-file-a,env-file-b')
    monkeypatch.setenv('COMPANY_AI_MAX_TASK_ATTEMPTS', '12')
    monkeypatch.setenv('REPORT_ITEM_JSON_RETRIES', '6')
    monkeypatch.setenv('REPORT_FINAL_JSON_RETRIES', '7')
    monkeypatch.setenv('REPORT_DENY_KEYS', '["secret","raw"]')
    monkeypatch.setenv('REPORT_DENY_PREFIXES', 'tmp_,raw_')
    monkeypatch.setenv('REPORT_MAX_DEPTH', '9')
    monkeypatch.setenv('REPORT_MAX_LIST_ITEMS', '42')
    monkeypatch.setenv('REPORT_MAX_STRING_CHARS', '5000')
    monkeypatch.setenv('REPORT_PREVIEW_AFTER_EACH_ITEM', 'false')

    loaded = load_application_config(str(tmp_path))
    assert loaded['COMPANY_AI_START_PROMPT'] == 'from-env'
    assert loaded['COMPANY_AI_PUBLIC_KEY_B64'] == 'env-key'
    assert loaded['COMPANY_AI_SIGN_SECRET'] == 'env-secret'
    assert loaded['COMPANY_AI_API_TIMEZONE'] == 'UTC'
    assert loaded['COMPANY_AI_SSE_DELAY_SECONDS'] == 3.5
    assert loaded['COMPANY_AI_DATASET_IDS'] == ['env-dataset']
    assert loaded['COMPANY_AI_FILE_IDS'] == ['env-file-a', 'env-file-b']
    assert loaded['COMPANY_AI_MAX_TASK_ATTEMPTS'] == 12
    assert loaded['REPORT_ITEM_JSON_RETRIES'] == 6
    assert loaded['REPORT_FINAL_JSON_RETRIES'] == 7
    assert loaded['REPORT_DENY_KEYS'] == ['secret', 'raw']
    assert loaded['REPORT_DENY_PREFIXES'] == ['tmp_', 'raw_']
    assert loaded['REPORT_MAX_DEPTH'] == 9
    assert loaded['REPORT_MAX_LIST_ITEMS'] == 42
    assert loaded['REPORT_MAX_STRING_CHARS'] == 5000
    assert loaded['REPORT_PREVIEW_AFTER_EACH_ITEM'] is False

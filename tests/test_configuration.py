import json

import pytest

from bootstrap import _load_env
from configuration import DEFAULT_JSON_ERROR_MESSAGE, load_application_config


def _set_required_env(monkeypatch, **overrides):
    values = {
        'ATLAS_MONGO_URI': 'mongodb://example/',
        'LOCAL_MONGO_URI': 'mongodb://local.example/',
        'FLASK_SECRET_KEY': 'secret',
        'COMPANY_AI_BASE_URL': 'https://company.example',
        'COMPANY_AI_USERNAME': 'owner',
        'COMPANY_AI_PASSWORD': 'password',
        'COMPANY_AI_START_PROMPT': 'initial',
        'COMPANY_AI_SUMMARY_PROMPT': 'Summary in ${language}.',
        'COMPANY_AI_PUBLIC_KEY_B64': 'public-key',
        'COMPANY_AI_SIGN_SECRET': 'sign-secret',
        'COMPANY_AI_MODEL': 'company-model',
        'RABBITMQ_URL': 'amqp://rabbit.example/',
        'RABBITMQ_INTAKE_QUEUE': 'summaries',
        'RABBITMQ_QUEUE_NAME': 'summaries',
        'RABBITMQ_GPU_QUEUE': 'gpu_preprocessing',
        'GPU_ENABLED': 'false',
    }
    values.update(overrides)
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_settings_load_from_environment(tmp_path, monkeypatch):
    _set_required_env(
        monkeypatch,
        COMPANY_AI_SSE_DELAY_SECONDS='1.5',
        COMPANY_AI_OWNER_ACCOUNT='owner',
        COMPANY_AI_PLATFORM_ID='6',
        COMPANY_AI_QA_TYPE='1',
        COMPANY_AI_FROM_SOURCE='report',
        COMPANY_AI_USE_THINK='false',
        COMPANY_AI_USER_PROMPT='prompt',
        COMPANY_AI_DATASET_IDS='["dataset"]',
        COMPANY_AI_FILE_IDS='["file"]',
        COMPANY_AI_CONTEXT_LIMIT='22000',
        COMPANY_AI_MAX_OUTPUT_TOKENS='2200',
        COMPANY_AI_TIMEOUT_SECONDS='90',
        COMPANY_AI_RETRIES='3',
        COMPANY_AI_PARALLEL_CHATS='6',
        COMPANY_AI_ENABLED='true',
        COMPANY_AI_DEFAULT_EWMA_SECONDS='55.5',
        AI_PROVIDER_METRICS_COLLECTION='provider_metrics',
        TAVILY_API_KEY='tavily-key',
        TAVILY_SEARCH_DEPTH='advanced',
        TAVILY_MAX_RESULTS='7',
        TAVILY_REQUEST_TIMEOUT_SECONDS='31',
        TAVILY_MAX_CONCURRENT_REQUESTS='2',
        ENRICHED_VENDOR_DOMAIN_MAP='{"Acme":"acme.example"}',
        ENRICHED_RESULTS_PER_TASK='5',
        ENRICHED_LLM_BASE_URL='https://llama.example/v1',
        ENRICHED_LLM_MODEL='qwen-test',
        ENRICHED_LLM_TIMEOUT_SECONDS='121',
        ENRICHED_LLM_MAX_OUTPUT_TOKENS='3000',
        ENRICHED_LLM_PAGE_CHARS='9000',
        RABBITMQ_MAX_PRIORITY='8',
        RABBITMQ_MAX_QUEUE_SIZE='19999',
        RABBITMQ_BACKGROUND_PRIORITY='2',
        RABBITMQ_REPORT_PRIORITY='8',
        COMPANY_AI_SCAN_INTERVAL_SECONDS='30',
        COMPANY_AI_STALE_PROCESSING_SECONDS='600',
        COMPANY_AI_REPORT_WAIT_TIMEOUT_SECONDS='45',
        REPORT_ITEM_JSON_RETRIES='4',
        REPORT_FINAL_JSON_RETRIES='5',
        REPORT_JSON_ERROR_MESSAGE='Configured JSON error: ${error}',
        REPORT_DENY_KEYS='["raw"]',
        REPORT_PREVIEW_AFTER_EACH_ITEM='false',
    )

    loaded = load_application_config(str(tmp_path))
    assert loaded['ATLAS_MONGO_URI'] == 'mongodb://example/'
    assert loaded['LOCAL_MONGO_URI'] == 'mongodb://local.example/'
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
    assert loaded['COMPANY_AI_DEFAULT_EWMA_SECONDS'] == 55.5
    assert loaded['AI_PROVIDER_METRICS_COLLECTION'] == 'provider_metrics'
    assert loaded['TAVILY_API_KEY'] == 'tavily-key'
    assert loaded['TAVILY_SEARCH_DEPTH'] == 'advanced'
    assert loaded['TAVILY_MAX_RESULTS'] == 7
    assert loaded['TAVILY_REQUEST_TIMEOUT_SECONDS'] == 31
    assert loaded['TAVILY_MAX_CONCURRENT_REQUESTS'] == 2
    assert loaded['ENRICHED_VENDOR_DOMAIN_MAP'] == {'Acme': 'acme.example'}
    assert loaded['ENRICHED_RESULTS_PER_TASK'] == 5
    assert loaded['ENRICHED_LLM_BASE_URL'] == 'https://llama.example/v1'
    assert loaded['ENRICHED_LLM_MODEL'] == 'qwen-test'
    assert loaded['ENRICHED_LLM_TIMEOUT_SECONDS'] == 121
    assert loaded['ENRICHED_LLM_MAX_OUTPUT_TOKENS'] == 3000
    assert loaded['ENRICHED_LLM_PAGE_CHARS'] == 9000
    assert loaded['RABBITMQ_URL'] == 'amqp://rabbit.example/'
    assert loaded['RABBITMQ_QUEUE_NAME'] == 'summaries'
    assert loaded['RABBITMQ_INTAKE_QUEUE'] == 'summaries'
    assert loaded['RABBITMQ_GPU_QUEUE'] == 'gpu_preprocessing'
    assert loaded['RABBITMQ_COMPANY_QUEUE'] == 'company_ai_processing'
    assert loaded['RABBITMQ_MAX_PRIORITY'] == 8
    assert loaded['RABBITMQ_MAX_QUEUE_SIZE'] == 19999
    assert loaded['RABBITMQ_BACKGROUND_PRIORITY'] == 2
    assert loaded['RABBITMQ_REPORT_PRIORITY'] == 8
    assert loaded['COMPANY_AI_SCAN_INTERVAL_SECONDS'] == 30
    assert loaded['COMPANY_AI_STALE_PROCESSING_SECONDS'] == 600
    assert loaded['COMPANY_AI_REPORT_WAIT_TIMEOUT_SECONDS'] == 45
    assert loaded['BACKGROUND_PREPROCESSING_ENABLED'] is False
    assert loaded['GPU_QUEUE_BACKLOG_LIMIT'] == 20
    assert loaded['GPU_ENABLED'] is False
    assert loaded['GPU_DEFAULT_EWMA_SECONDS'] == 30
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
    monkeypatch.setenv('BACKGROUND_PREPROCESSING_ENABLED', 'true')
    background_enabled = load_application_config(str(tmp_path))
    assert background_enabled['BACKGROUND_PREPROCESSING_ENABLED'] is True


def test_separate_mongo_connections(tmp_path, monkeypatch):
    _set_required_env(
        monkeypatch,
        ATLAS_MONGO_URI='mongodb+srv://atlas.example/',
        LOCAL_MONGO_URI='mongodb://local.example/',
        LOCAL_DATABASE='local_app',
    )

    loaded = load_application_config(str(tmp_path))
    assert loaded['ATLAS_MONGO_URI'] == 'mongodb+srv://atlas.example/'
    assert loaded['LOCAL_MONGO_URI'] == 'mongodb://local.example/'
    assert loaded['LOCAL_DATABASE'] == 'local_app'

    monkeypatch.setenv('LOCAL_MONGO_URI', 'mongodb://environment-local/')
    assert load_application_config(str(tmp_path))['LOCAL_MONGO_URI'] == (
        'mongodb://environment-local/'
    )


def test_mongo_connections_are_required(tmp_path, monkeypatch):
    monkeypatch.delenv('ATLAS_MONGO_URI', raising=False)
    monkeypatch.delenv('LOCAL_MONGO_URI', raising=False)
    monkeypatch.delenv('FLASK_SECRET_KEY', raising=False)

    with pytest.raises(ValueError, match='Missing required environment variable'):
        load_application_config(str(tmp_path))


def test_worker_configuration_requires_atlas_but_not_local_mongo(tmp_path, monkeypatch):
    monkeypatch.setenv('ATLAS_MONGO_URI', 'mongodb://atlas.example/')
    monkeypatch.delenv('LOCAL_MONGO_URI', raising=False)
    monkeypatch.delenv('FLASK_SECRET_KEY', raising=False)

    loaded = load_application_config(str(tmp_path), require_local=False)
    assert loaded['ATLAS_MONGO_URI'] == 'mongodb://atlas.example/'
    assert loaded['LOCAL_MONGO_URI'] == ''
    assert loaded['AI_TASK_COLLECTION'] == 'ai_generation_tasks'
    assert loaded['AI_PROVIDER_METRICS_COLLECTION'] == 'ai_provider_metrics'


def test_environment_list_and_report_defaults(tmp_path, monkeypatch):
    _set_required_env(monkeypatch)
    monkeypatch.delenv('REPORT_JSON_ERROR_MESSAGE', raising=False)
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
    assert loaded['REPORT_JSON_ERROR_MESSAGE'] == DEFAULT_JSON_ERROR_MESSAGE


def test_settings_load_from_config_json(tmp_path, monkeypatch):
    _set_required_env(monkeypatch)
    for name in (
        'COMPANY_AI_BASE_URL', 'COMPANY_AI_USERNAME', 'COMPANY_AI_START_PROMPT',
        'COMPANY_AI_SUMMARY_PROMPT', 'COMPANY_AI_MODEL', 'RABBITMQ_INTAKE_QUEUE',
        'RABBITMQ_GPU_QUEUE', 'COMPANY_AI_PARALLEL_CHATS', 'REPORT_MAX_DEPTH',
    ):
        monkeypatch.delenv(name, raising=False)

    config_dir = tmp_path / 'config'
    config_dir.mkdir()
    (config_dir / 'config.json').write_text(
        json.dumps({
            'company_ai': {
                'base_url': 'https://json.example',
                'username': 'json-user',
                'start_prompt': 'json-start',
                'summary_prompt': 'json-summary',
                'model': 'json-model',
                'parallel_chats': 2,
            },
            'rabbitmq': {
                'intake_queue': 'json-intake',
                'gpu_queue': 'json-gpu',
            },
            'report': {
                'max_depth': 11,
            },
        }),
        encoding='utf-8',
    )

    loaded = load_application_config(str(tmp_path))
    assert loaded['COMPANY_AI_BASE_URL'] == 'https://json.example'
    assert loaded['COMPANY_AI_USERNAME'] == 'json-user'
    assert loaded['COMPANY_AI_START_PROMPT'] == 'json-start'
    assert loaded['COMPANY_AI_SUMMARY_PROMPT'] == 'json-summary'
    assert loaded['COMPANY_AI_MODEL'] == 'json-model'
    assert loaded['COMPANY_AI_PARALLEL_CHATS'] == 2
    assert loaded['RABBITMQ_INTAKE_QUEUE'] == 'json-intake'
    assert loaded['RABBITMQ_GPU_QUEUE'] == 'json-gpu'
    assert loaded['REPORT_MAX_DEPTH'] == 11


def test_load_dotenv_from_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name in (
        'ATLAS_MONGO_URI', 'LOCAL_MONGO_URI', 'FLASK_SECRET_KEY',
        'COMPANY_AI_BASE_URL', 'COMPANY_AI_USERNAME', 'COMPANY_AI_PASSWORD',
        'COMPANY_AI_START_PROMPT', 'COMPANY_AI_SUMMARY_PROMPT',
        'COMPANY_AI_PUBLIC_KEY_B64', 'COMPANY_AI_SIGN_SECRET', 'COMPANY_AI_MODEL',
        'RABBITMQ_URL',
    ):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / '.env').write_text(
        '\n'.join([
            'ATLAS_MONGO_URI=mongodb://dotenv-atlas/',
            'LOCAL_MONGO_URI=mongodb://dotenv-local/',
            'FLASK_SECRET_KEY=dotenv-secret',
            'COMPANY_AI_BASE_URL=https://dotenv.example',
            'COMPANY_AI_USERNAME=dotenv-user',
            'COMPANY_AI_PASSWORD=dotenv-password',
            'COMPANY_AI_START_PROMPT=dotenv-start',
            'COMPANY_AI_SUMMARY_PROMPT=dotenv-summary',
            'COMPANY_AI_PUBLIC_KEY_B64=dotenv-key',
            'COMPANY_AI_SIGN_SECRET=dotenv-sign',
            'COMPANY_AI_MODEL=dotenv-model',
            'RABBITMQ_URL=amqp://dotenv/',
        ]),
        encoding='utf-8',
    )

    _load_env(str(tmp_path))
    loaded = load_application_config(str(tmp_path))
    assert loaded['ATLAS_MONGO_URI'] == 'mongodb://dotenv-atlas/'
    assert loaded['LOCAL_MONGO_URI'] == 'mongodb://dotenv-local/'
    assert loaded['SECRET_KEY'] == 'dotenv-secret'
    assert loaded['COMPANY_AI_BASE_URL'] == 'https://dotenv.example'

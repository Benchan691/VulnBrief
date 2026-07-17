import json

import pytest

from core.bootstrap import _load_env
from core.config import DEFAULT_JSON_ERROR_MESSAGE, load_application_config


def _set_required_env(monkeypatch, **overrides):
    values = {
        'LOCAL_MONGO_URI': 'mongodb://local.example/',
        'FLASK_SECRET_KEY': 'secret',
    }
    values.update(overrides)
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('MONGO_URI', raising=False)
    if 'MONGO_URI' in overrides:
        monkeypatch.setenv('MONGO_URI', overrides['MONGO_URI'])


def test_settings_load_from_environment(tmp_path, monkeypatch):
    _set_required_env(
        monkeypatch,
        TAVILY_API_KEY='tavily-key',
        TAVILY_API_KEYS='["tavily-a","tavily-b"]',
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
        REPORT_ITEM_JSON_RETRIES='4',
        REPORT_FINAL_JSON_RETRIES='5',
        REPORT_JSON_ERROR_MESSAGE='Configured JSON error: ${error}',
        REPORT_DENY_KEYS='["raw"]',
        REPORT_PREVIEW_AFTER_EACH_ITEM='false',
    )

    loaded = load_application_config(str(tmp_path))
    assert loaded['MONGO_URI'] == 'mongodb://local.example/'
    assert loaded['LOCAL_MONGO_URI'] == 'mongodb://local.example/'
    assert loaded['LOCAL_DATABASE'] == 'web'
    assert loaded['TAVILY_API_KEY'] == 'tavily-key'
    assert loaded['TAVILY_API_KEYS'] == ['tavily-a', 'tavily-b']
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
    assert loaded['REPORT_ITEM_JSON_RETRIES'] == 4
    assert loaded['REPORT_FINAL_JSON_RETRIES'] == 5
    assert loaded['REPORT_JSON_ERROR_MESSAGE'] == 'Configured JSON error: ${error}'
    assert loaded['REPORT_DENY_KEYS'] == ['raw']
    assert loaded['REPORT_PREVIEW_AFTER_EACH_ITEM'] is False

    monkeypatch.setenv('REPORT_JSON_ERROR_MESSAGE', 'Environment JSON error: ${error}')
    overridden = load_application_config(str(tmp_path))
    assert overridden['REPORT_JSON_ERROR_MESSAGE'] == 'Environment JSON error: ${error}'


def test_mongo_uri_alias_overrides_local_uri(tmp_path, monkeypatch):
    _set_required_env(
        monkeypatch,
        MONGO_URI='mongodb://mongo-alias/',
        LOCAL_MONGO_URI='mongodb://local.example/',
        LOCAL_DATABASE='local_app',
    )

    loaded = load_application_config(str(tmp_path))
    assert loaded['MONGO_URI'] == 'mongodb://mongo-alias/'
    assert loaded['LOCAL_MONGO_URI'] == 'mongodb://mongo-alias/'
    assert loaded['LOCAL_DATABASE'] == 'local_app'

    monkeypatch.setenv('LOCAL_MONGO_URI', 'mongodb://environment-local/')
    assert load_application_config(str(tmp_path))['LOCAL_MONGO_URI'] == (
        'mongodb://mongo-alias/'
    )


def test_web_database_uses_web_database_name(monkeypatch):
    from core import database as mongo

    class FakeClient:
        def __getitem__(self, name):
            return name

    monkeypatch.setattr(mongo, '_config', {
        'LOCAL_DATABASE': 'local_app',
        'WEB_DATABASE': 'web_app',
        'MONGO_URI': 'mongodb://local.example/',
    })
    monkeypatch.setattr(mongo, '_client', FakeClient())

    assert mongo.get_web_database() == 'web_app'


def test_vulnerabilities_database_uses_shared_client(monkeypatch):
    from core import database as mongo

    class FakeClient:
        def __getitem__(self, name):
            return name

    fake_client = FakeClient()
    monkeypatch.setattr(mongo, '_config', {
        'LOCAL_DATABASE': 'web',
        'WEB_DATABASE': 'web',
        'VULNERABILITIES_DATABASE': 'vulnerabilities',
        'MONGO_URI': 'mongodb://local.example/',
    })
    monkeypatch.setattr(mongo, '_client', fake_client)

    assert mongo.get_web_database() == 'web'
    assert mongo.get_vulnerabilities_database() == 'vulnerabilities'
    assert mongo.get_mongo_client() is fake_client


def test_mongo_connections_are_required(tmp_path, monkeypatch):
    monkeypatch.delenv('MONGO_URI', raising=False)
    monkeypatch.delenv('LOCAL_MONGO_URI', raising=False)
    monkeypatch.delenv('FLASK_SECRET_KEY', raising=False)

    with pytest.raises(ValueError, match='Missing required environment variable'):
        load_application_config(str(tmp_path))


def test_environment_list_and_report_defaults(tmp_path, monkeypatch):
    _set_required_env(monkeypatch)
    monkeypatch.delenv('REPORT_JSON_ERROR_MESSAGE', raising=False)
    monkeypatch.setenv('REPORT_ITEM_JSON_RETRIES', '6')
    monkeypatch.setenv('REPORT_FINAL_JSON_RETRIES', '7')
    monkeypatch.setenv('REPORT_DENY_KEYS', '["secret","raw"]')
    monkeypatch.setenv('REPORT_DENY_PREFIXES', 'tmp_,raw_')
    monkeypatch.setenv('REPORT_MAX_DEPTH', '9')
    monkeypatch.setenv('REPORT_MAX_LIST_ITEMS', '42')
    monkeypatch.setenv('REPORT_MAX_STRING_CHARS', '5000')
    monkeypatch.setenv('REPORT_PREVIEW_AFTER_EACH_ITEM', 'false')

    loaded = load_application_config(str(tmp_path))
    assert loaded['REPORT_ITEM_JSON_RETRIES'] == 6
    assert loaded['REPORT_FINAL_JSON_RETRIES'] == 7
    assert loaded['REPORT_DENY_KEYS'] == ['secret', 'raw']
    assert loaded['REPORT_DENY_PREFIXES'] == ['tmp_', 'raw_']
    assert loaded['REPORT_MAX_DEPTH'] == 9
    assert loaded['REPORT_MAX_LIST_ITEMS'] == 42
    assert loaded['REPORT_MAX_STRING_CHARS'] == 5000
    assert loaded['REPORT_PREVIEW_AFTER_EACH_ITEM'] is False
    assert loaded['REPORT_JSON_ERROR_MESSAGE'] == DEFAULT_JSON_ERROR_MESSAGE


def test_settings_load_prompts_from_config_json(tmp_path, monkeypatch):
    _set_required_env(monkeypatch)

    config_dir = tmp_path / 'config'
    config_dir.mkdir()
    (config_dir / 'config.json').write_text(
        json.dumps({
            'prompts': {
                'evidence_extraction_system': 'Configured evidence prompt.',
                'json_error_message': 'Configured JSON error: ${error}',
            },
        }),
        encoding='utf-8',
    )

    loaded = load_application_config(str(tmp_path))
    assert loaded['AI_PROMPTS']['evidence_extraction_system'] == 'Configured evidence prompt.'
    assert loaded['REPORT_JSON_ERROR_MESSAGE'] == 'Configured JSON error: ${error}'
    assert loaded['AI_PROMPTS']['json_error_message'] == 'Configured JSON error: ${error}'


def test_settings_load_from_config_json(tmp_path, monkeypatch):
    _set_required_env(monkeypatch)
    monkeypatch.delenv('REPORT_MAX_DEPTH', raising=False)

    config_dir = tmp_path / 'config'
    config_dir.mkdir()
    (config_dir / 'config.json').write_text(
        json.dumps({
            'report': {
                'max_depth': 11,
            },
        }),
        encoding='utf-8',
    )

    loaded = load_application_config(str(tmp_path))
    assert loaded['REPORT_MAX_DEPTH'] == 11


def test_single_tavily_key_backfills_key_list(tmp_path, monkeypatch):
    _set_required_env(monkeypatch, TAVILY_API_KEY='legacy-key')
    monkeypatch.delenv('TAVILY_API_KEYS', raising=False)

    loaded = load_application_config(str(tmp_path))

    assert loaded['TAVILY_API_KEYS'] == ['legacy-key']


def test_load_dotenv_from_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name in (
        'MONGO_URI', 'LOCAL_MONGO_URI', 'FLASK_SECRET_KEY',
    ):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / '.env').write_text(
        '\n'.join([
            'LOCAL_MONGO_URI=mongodb://dotenv-local/',
            'FLASK_SECRET_KEY=dotenv-secret',
        ]),
        encoding='utf-8',
    )

    _load_env(str(tmp_path))
    loaded = load_application_config(str(tmp_path))
    assert loaded['MONGO_URI'] == 'mongodb://dotenv-local/'
    assert loaded['LOCAL_MONGO_URI'] == 'mongodb://dotenv-local/'
    assert loaded['SECRET_KEY'] == 'dotenv-secret'

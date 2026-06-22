import json

import pytest

from bootstrap import _load_env
from configuration import DEFAULT_JSON_ERROR_MESSAGE, load_application_config


def _set_required_env(monkeypatch, **overrides):
    values = {
        'ATLAS_MONGO_URI': 'mongodb://example/',
        'LOCAL_MONGO_URI': 'mongodb://local.example/',
        'FLASK_SECRET_KEY': 'secret',
    }
    values.update(overrides)
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_settings_load_from_environment(tmp_path, monkeypatch):
    _set_required_env(
        monkeypatch,
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
    assert loaded['REPORT_ITEM_JSON_RETRIES'] == 4
    assert loaded['REPORT_FINAL_JSON_RETRIES'] == 5
    assert loaded['REPORT_JSON_ERROR_MESSAGE'] == 'Configured JSON error: ${error}'
    assert loaded['REPORT_DENY_KEYS'] == ['raw']
    assert loaded['REPORT_PREVIEW_AFTER_EACH_ITEM'] is False

    monkeypatch.setenv('REPORT_JSON_ERROR_MESSAGE', 'Environment JSON error: ${error}')
    overridden = load_application_config(str(tmp_path))
    assert overridden['REPORT_JSON_ERROR_MESSAGE'] == 'Environment JSON error: ${error}'


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


def test_load_dotenv_from_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name in (
        'ATLAS_MONGO_URI', 'LOCAL_MONGO_URI', 'FLASK_SECRET_KEY',
    ):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / '.env').write_text(
        '\n'.join([
            'ATLAS_MONGO_URI=mongodb://dotenv-atlas/',
            'LOCAL_MONGO_URI=mongodb://dotenv-local/',
            'FLASK_SECRET_KEY=dotenv-secret',
        ]),
        encoding='utf-8',
    )

    _load_env(str(tmp_path))
    loaded = load_application_config(str(tmp_path))
    assert loaded['ATLAS_MONGO_URI'] == 'mongodb://dotenv-atlas/'
    assert loaded['LOCAL_MONGO_URI'] == 'mongodb://dotenv-local/'
    assert loaded['SECRET_KEY'] == 'dotenv-secret'

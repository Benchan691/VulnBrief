from unittest.mock import patch

import pytest
import requests

from enriched_report.llama_client import (
    EnrichedLlamaClient,
    EnrichedLLMError,
    _completion_message_text,
    _message_text,
)


def _config(**overrides):
    base = {
        'ENRICHED_LLM_BASE_URL': 'http://llama.example/v1',
        'ENRICHED_LLM_MODEL': 'test-model',
        'ENRICHED_LLM_CONNECTION_RETRIES': 2,
        'ENRICHED_LLM_RETRY_WAIT_SECONDS': 0,
    }
    base.update(overrides)
    return base


def test_completion_retries_connection_errors_then_succeeds():
    client = EnrichedLlamaClient(_config())
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"choices":[{"message":{"content":"{\\"ok\\": true}"}}]}'

    with patch('enriched_report.llama_client._http_post') as post, patch(
        'enriched_report.llama_client.time.sleep',
    ):
        post.side_effect = [
            requests.ConnectionError('connection refused'),
            requests.ConnectionError('connection refused'),
            response,
        ]
        content = client._completion([{'role': 'user', 'content': 'ping'}])

    assert content == '{"ok": true}'
    assert post.call_count == 3


def test_completion_raises_after_connection_retries_exhausted():
    client = EnrichedLlamaClient(_config(ENRICHED_LLM_CONNECTION_RETRIES=1))

    with patch('enriched_report.llama_client._http_post') as post, patch(
        'enriched_report.llama_client.time.sleep',
    ):
        post.side_effect = requests.ConnectionError('connection refused')
        with pytest.raises(requests.ConnectionError):
            client._completion([{'role': 'user', 'content': 'ping'}])

    assert post.call_count == 2


def test_evidence_and_report_token_limits():
    client = EnrichedLlamaClient(_config(
        ENRICHED_LLM_MAX_OUTPUT_TOKENS=2048,
        ENRICHED_LLM_EVIDENCE_MAX_OUTPUT_TOKENS=1024,
        ENRICHED_LLM_REPORT_MAX_OUTPUT_TOKENS=4096,
    ))
    assert client.evidence_max_output_tokens == 1024
    assert client.report_max_output_tokens == 4096


def test_message_text_prefers_content():
    assert _message_text({'content': '{"ok": true}', 'reasoning_content': 'thinking'}) == '{"ok": true}'


def test_message_text_falls_back_to_reasoning_content():
    assert _message_text({'content': '', 'reasoning_content': '{"ok": true}'}) == '{"ok": true}'


def test_message_text_strips_think_blocks():
    wrapped = '<' + 'think' + '>hidden</' + 'think' + '>{\"ok\": true}'
    text = _message_text({'content': wrapped})
    assert text == '{"ok": true}'


def test_completion_message_text_from_reasoning_only_response():
    body = {
        'choices': [{
            'message': {
                'role': 'assistant',
                'content': '',
                'reasoning_content': '{"ok": true}',
            },
        }],
    }
    assert _completion_message_text(body) == '{"ok": true}'


def test_omits_response_format_when_strict_schema_disabled():
    client = EnrichedLlamaClient(_config(ENRICHED_LLM_USE_STRICT_SCHEMA=False))
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"choices":[{"message":{"content":"{\\"ok\\": true}"}}]}'
    schema = {'type': 'object', 'properties': {'ok': {'type': 'boolean'}}}

    with patch('enriched_report.llama_client._http_post') as post:
        post.return_value = response
        client._completion(
            [{'role': 'user', 'content': 'ping'}],
            schema=schema,
            schema_name='test_schema',
        )

    payload = post.call_args[0][1]
    assert 'response_format' not in payload
    assert payload['max_tokens'] == 2048


def test_complete_json_retry_does_not_accumulate_assistant_history():
    client = EnrichedLlamaClient(_config(ENRICHED_LLM_JSON_RETRIES=2))
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"choices":[{"message":{"content":"not json"}}]}'

    with patch('enriched_report.llama_client._http_post') as post:
        post.return_value = response
        with pytest.raises(EnrichedLLMError):
            client.complete_json('system', 'user', schema={'type': 'object'})

    assert post.call_count == 3
    for call in post.call_args_list:
        messages = call[0][1]['messages']
        assert len(messages) <= 3


def test_prepare_system_prompt_adds_no_think():
    client = EnrichedLlamaClient(_config(ENRICHED_LLM_DISABLE_THINKING=True))
    prepared = client._prepare_system_prompt('Return JSON only.')
    assert prepared.startswith('/no_think\n')


def test_prepare_system_prompt_skips_duplicate_no_think():
    client = EnrichedLlamaClient(_config(ENRICHED_LLM_DISABLE_THINKING=True))
    prepared = client._prepare_system_prompt('/no_think\nReturn JSON only.')
    assert prepared == '/no_think\nReturn JSON only.'

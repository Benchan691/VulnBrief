from unittest.mock import patch

import pytest
import requests

from reports.enriched.llama_client import (
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

    with patch('reports.enriched.llama_client._http_post') as post, patch(
        'reports.enriched.llama_client.time.sleep',
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

    with patch('reports.enriched.llama_client._http_post') as post, patch(
        'reports.enriched.llama_client.time.sleep',
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


def test_prepare_system_prompt_adds_no_think():
    client = EnrichedLlamaClient(_config(ENRICHED_LLM_DISABLE_THINKING=True))
    prepared = client._prepare_system_prompt('Return JSON only.')
    assert prepared.startswith('/no_think\n')


def test_prepare_system_prompt_skips_duplicate_no_think():
    client = EnrichedLlamaClient(_config(ENRICHED_LLM_DISABLE_THINKING=True))
    prepared = client._prepare_system_prompt('/no_think\nReturn JSON only.')
    assert prepared == '/no_think\nReturn JSON only.'


def test_complete_text_omits_response_format():
    client = EnrichedLlamaClient(_config())
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"choices":[{"message":{"content":"Plain answer."}}]}'

    with patch('reports.enriched.llama_client._http_post') as post:
        post.return_value = response
        text, _ = client.complete_text('system', 'user')

    assert text == 'Plain answer.'
    payload = post.call_args[0][1]
    assert 'response_format' not in payload


def test_complete_text_raises_on_empty_response():
    client = EnrichedLlamaClient(_config())
    empty = requests.Response()
    empty.status_code = 200
    empty._content = b'{"choices":[{"message":{"content":""}}]}'

    with patch('reports.enriched.llama_client._http_post') as post:
        post.return_value = empty
        with pytest.raises(EnrichedLLMError, match='empty response'):
            client.complete_text('system', 'user')

    assert post.call_count == 1

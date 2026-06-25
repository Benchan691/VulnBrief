import json
import logging
import re
import threading
import time

import requests
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)
NO_THINK_DIRECTIVE = '/no_think'
_REQUEST_LOCK = threading.Lock()
_HTTP_HEADERS = {
    'Accept': 'application/json',
    'Connection': 'close',
}


class EnrichedLLMError(RuntimeError):
    pass


def _strip_think_blocks(text):
    if not text:
        return ''
    think_block = re.compile(
        r'<' + 'think' + r'(?:ing)?>\s*.*?\s*</' + 'think' + r'(?:ing)?>',
        re.DOTALL | re.IGNORECASE,
    )
    stripped = think_block.sub('', text)
    stripped = re.sub(r'\[think\].*?\[/think\]', '', stripped, flags=re.DOTALL | re.IGNORECASE)
    return stripped.strip()


def _message_text(message):
    if not isinstance(message, dict):
        logger.debug('completion message was not a dict: %s', type(message).__name__)
        return ''
    content = str(message.get('content') or '').strip()
    reasoning = str(message.get('reasoning_content') or '').strip()
    logger.debug(
        'completion text sources content_chars=%d reasoning_chars=%d',
        len(content),
        len(reasoning),
    )
    # #endregion
    if content:
        return _strip_think_blocks(content)
    if reasoning:
        logger.info('enriched llm using reasoning_content fallback (content was empty)')
        return _strip_think_blocks(reasoning)
    return ''


def _completion_message_text(response_json):
    try:
        message = response_json['choices'][0]['message']
    except (KeyError, IndexError, TypeError) as exc:
        logger.debug('completion payload had unexpected shape: %s', type(response_json).__name__)
        raise EnrichedLLMError('llama-server returned an unexpected completion payload.') from exc
    text = _message_text(message)
    if not text:
        raise EnrichedLLMError('llama-server returned an empty response.')
    return text


def _http_post(url, payload, timeout):
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=0)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    try:
        return session.post(
            url,
            json=payload,
            headers=_HTTP_HEADERS,
            timeout=timeout,
        )
    finally:
        session.close()


class EnrichedLlamaClient:
    def __init__(self, config):
        base_url = (config.get('ENRICHED_LLM_BASE_URL') or '').strip()
        if not base_url:
            raise ValueError('ENRICHED_LLM_BASE_URL must be configured for enriched_weekly reports.')
        self.base_url = base_url.rstrip('/')
        self.model = config.get('ENRICHED_LLM_MODEL') or 'qwen-local'
        self.connect_timeout = max(1, int(config.get('ENRICHED_LLM_CONNECT_TIMEOUT_SECONDS', 30)))
        self.timeout = int(config.get('ENRICHED_LLM_TIMEOUT_SECONDS', 120))
        self.max_output_tokens = int(config.get('ENRICHED_LLM_MAX_OUTPUT_TOKENS', 2048))
        self.evidence_max_output_tokens = int(
            config.get('ENRICHED_LLM_EVIDENCE_MAX_OUTPUT_TOKENS', min(self.max_output_tokens, 1024)),
        )
        self.report_max_output_tokens = int(
            config.get('ENRICHED_LLM_REPORT_MAX_OUTPUT_TOKENS', min(self.max_output_tokens, 4096)),
        )
        self.connection_retries = max(0, int(config.get('ENRICHED_LLM_CONNECTION_RETRIES', 5)))
        self.retry_wait_seconds = max(0, int(config.get('ENRICHED_LLM_RETRY_WAIT_SECONDS', 10)))
        self.disable_thinking = bool(config.get('ENRICHED_LLM_DISABLE_THINKING', True))

    def _prepare_system_prompt(self, system_prompt):
        if not self.disable_thinking:
            return system_prompt
        if system_prompt.lstrip().startswith(NO_THINK_DIRECTIVE):
            return system_prompt
        return NO_THINK_DIRECTIVE + '\n' + system_prompt

    def _timeouts(self):
        return (self.connect_timeout, self.timeout)

    def _retry_wait(self, attempt):
        return self.retry_wait_seconds * (attempt + 1)

    def _payload_size(self, payload):
        return len(json.dumps(payload, ensure_ascii=False, default=str))

    def _completion(self, messages, max_output_tokens=None):
        output_tokens = max_output_tokens or self.max_output_tokens
        payload = {
            'model': self.model,
            'messages': messages,
            'temperature': 0.1,
            'max_tokens': output_tokens,
        }
        url = self.base_url + '/chat/completions'
        payload_chars = self._payload_size(payload)
        last_error = None
        with _REQUEST_LOCK:
            for attempt in range(self.connection_retries + 1):
                logger.info(
                    'enriched llm request attempt=%d/%d model=%s url=%s messages=%d '
                    'max_tokens=%d payload_chars=%d connect_timeout=%ss read_timeout=%ss',
                    attempt + 1,
                    self.connection_retries + 1,
                    self.model,
                    url,
                    len(messages),
                    output_tokens,
                    payload_chars,
                    self.connect_timeout,
                    self.timeout,
                )
                try:
                    response = _http_post(url, payload, self._timeouts())
                    logger.info(
                        'enriched llm response status=%s url=%s body_chars=%d',
                        response.status_code,
                        url,
                        len(response.text),
                    )
                    response.raise_for_status()
                    return _completion_message_text(response.json())
                except requests.RequestException as exc:
                    last_error = exc
                    wait_seconds = self._retry_wait(attempt)
                    logger.warning(
                        'enriched llm request failed attempt=%d/%d model=%s url=%s error=%s',
                        attempt + 1,
                        self.connection_retries + 1,
                        self.model,
                        url,
                        exc,
                    )
                    if attempt >= self.connection_retries:
                        break
                    logger.info(
                        'enriched llm waiting %ss before retry (server may be restarting)',
                        wait_seconds,
                    )
                    time.sleep(wait_seconds)
        logger.error(
            'enriched llm request exhausted retries model=%s url=%s error=%s',
            self.model,
            url,
            last_error,
        )
        raise last_error

    def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
        messages = [
            {'role': 'system', 'content': self._prepare_system_prompt(system_prompt)},
            {'role': 'user', 'content': user_prompt},
        ]
        try:
            return self._completion(messages, max_output_tokens=max_output_tokens), {}
        except requests.RequestException as exc:
            raise EnrichedLLMError(str(exc)) from exc

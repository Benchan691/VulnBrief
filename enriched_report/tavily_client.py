import logging

import requests

logger = logging.getLogger(__name__)


def _http_status(exc):
    response = getattr(exc, 'response', None)
    return getattr(response, 'status_code', None)


def _quota_like(exc):
    status = _http_status(exc)
    if status in {401, 403, 429}:
        return True
    text = str(exc).lower()
    return any(word in text for word in ('quota', 'credit', 'rate limit', 'rate-limit', 'limit exceeded'))


def _keys(config, list_name, single_name):
    keys = list(config.get(list_name) or [])
    if not keys and config.get(single_name):
        keys = [config.get(single_name)]
    return [str(key).strip() for key in keys if str(key).strip()]


class TavilyClient:
    def __init__(
        self,
        api_key,
        search_depth='basic',
        max_results=5,
        timeout_seconds=30,
        endpoint='https://api.tavily.com/search',
    ):
        if not api_key:
            raise ValueError('TAVILY_API_KEY must be configured for enriched_weekly reports.')
        self.api_key = api_key
        self.search_depth = search_depth
        self.max_results = int(max_results)
        self.timeout_seconds = int(timeout_seconds)
        self.endpoint = endpoint
        self.provider = 'tavily'

    def search(self, query):
        payload = {
            'api_key': self.api_key,
            'query': query,
            'search_depth': self.search_depth,
            'max_results': self.max_results,
            'include_raw_content': True,
        }
        response = requests.post(
            self.endpoint,
            headers={'Authorization': f'Bearer {self.api_key}'},
            json=payload,
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        body = response.json()
        return body.get('results') or []


class ExaClient:
    def __init__(
        self,
        api_key,
        search_type='auto',
        max_results=5,
        timeout_seconds=30,
        endpoint='https://api.exa.ai/search',
    ):
        if not api_key:
            raise ValueError('EXA_API_KEYS must be configured for Exa search.')
        self.api_key = api_key
        self.search_type = search_type
        self.max_results = int(max_results)
        self.timeout_seconds = int(timeout_seconds)
        self.endpoint = endpoint
        self.provider = 'exa'

    def search(self, query):
        response = requests.post(
            self.endpoint,
            headers={'x-api-key': self.api_key, 'Content-Type': 'application/json'},
            json={
                'query': query,
                'type': self.search_type,
                'numResults': self.max_results,
                'contents': {
                    'highlights': True,
                    'text': {'maxCharacters': 60000},
                },
            },
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return [self._result(item) for item in (response.json().get('results') or [])]

    def _result(self, item):
        highlights = item.get('highlights') or []
        snippet = '\n'.join(str(part) for part in highlights if part)
        page_content = item.get('text') or snippet
        return {
            'url': item.get('url') or '',
            'title': item.get('title') or '',
            'snippet': snippet,
            'page_content': page_content,
            'score': item.get('score'),
            'source_api': 'exa',
        }


class FailoverSearchClient:
    def __init__(self, clients):
        self.clients = list(clients)
        self.disabled = set()
        if not self.clients:
            raise ValueError('At least one Tavily or Exa API key must be configured.')

    def search(self, query):
        last_error = None
        for index, client in enumerate(self.clients):
            if index in self.disabled:
                continue
            provider = getattr(client, 'provider', client.__class__.__name__.lower())
            try:
                logger.info('search attempt provider=%s key_index=%d', provider, index + 1)
                results = client.search(query)
                logger.info(
                    'search success provider=%s key_index=%d results=%d',
                    provider,
                    index + 1,
                    len(results),
                )
                return results
            except Exception as exc:
                last_error = exc
                if _quota_like(exc):
                    self.disabled.add(index)
                logger.warning(
                    'search failed provider=%s key_index=%d disabled=%s error=%s',
                    provider,
                    index + 1,
                    index in self.disabled,
                    exc,
                )
        raise last_error or RuntimeError('No search providers configured.')


def build_search_client(config):
    clients = [
        TavilyClient(
            key,
            config.get('TAVILY_SEARCH_DEPTH', 'basic'),
            config.get('TAVILY_MAX_RESULTS', 5),
            config.get('TAVILY_REQUEST_TIMEOUT_SECONDS', 30),
        )
        for key in _keys(config, 'TAVILY_API_KEYS', 'TAVILY_API_KEY')
    ]
    clients.extend(
        ExaClient(
            key,
            config.get('EXA_SEARCH_TYPE', 'auto'),
            config.get('EXA_MAX_RESULTS', config.get('TAVILY_MAX_RESULTS', 5)),
            config.get(
                'EXA_REQUEST_TIMEOUT_SECONDS',
                config.get('TAVILY_REQUEST_TIMEOUT_SECONDS', 30),
            ),
        )
        for key in _keys(config, 'EXA_API_KEYS', 'EXA_API_KEY')
    )
    return FailoverSearchClient(clients)

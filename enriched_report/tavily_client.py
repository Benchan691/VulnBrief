import logging

import requests

logger = logging.getLogger(__name__)


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


class SearXNGClient:
    def __init__(
        self,
        base_url,
        max_results=5,
        timeout_seconds=30,
        fetch_timeout_seconds=30,
        max_snippet_chars=8192,
    ):
        if not base_url:
            raise ValueError('SEARXNG_BASE_URL must be configured for SearXNG search.')
        self.base_url = base_url.rstrip('/')
        self.max_results = int(max_results)
        self.timeout_seconds = int(timeout_seconds)
        self.fetch_timeout_seconds = int(fetch_timeout_seconds)
        self.max_snippet_chars = max(1, int(max_snippet_chars))
        self.provider = 'searxng'

    def search(self, query):
        response = requests.get(
            f'{self.base_url}/search',
            params={'q': query, 'format': 'json'},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        body = response.json()
        results = []
        for item in (body.get('results') or [])[:self.max_results]:
            parsed = self._result(item)
            if parsed is not None:
                results.append(parsed)
        return results

    def _result(self, item):
        url = (item.get('url') or '').strip()
        if not url:
            return None
        snippet = (item.get('content') or item.get('snippet') or '').strip()
        if not snippet:
            logger.info('searxng snippet skipped url=%s reason=empty', url)
            return None
        if len(snippet) > self.max_snippet_chars:
            logger.info(
                'searxng snippet skipped url=%s reason=too_long chars=%d limit=%d',
                url,
                len(snippet),
                self.max_snippet_chars,
            )
            return None
        return {
            'url': url,
            'title': item.get('title') or '',
            'snippet': snippet,
            'page_content': snippet,
            'score': item.get('score'),
            'source_api': 'searxng',
        }


def build_search_client(config):
    if config.get('SEARXNG_BASE_URL'):
        return SearXNGClient(
            config.get('SEARXNG_BASE_URL'),
            config.get('SEARXNG_MAX_RESULTS', config.get('TAVILY_MAX_RESULTS', 5)),
            config.get(
                'SEARXNG_REQUEST_TIMEOUT_SECONDS',
                config.get('TAVILY_REQUEST_TIMEOUT_SECONDS', 30),
            ),
            config.get(
                'SEARXNG_FETCH_TIMEOUT_SECONDS',
                config.get('TAVILY_REQUEST_TIMEOUT_SECONDS', 30),
            ),
            config.get('SEARXNG_MAX_SNIPPET_CHARS', 8192),
        )
    keys = _keys(config, 'TAVILY_API_KEYS', 'TAVILY_API_KEY')
    if not keys:
        raise ValueError('TAVILY_API_KEYS or SEARXNG_BASE_URL must be configured.')
    return TavilyClient(
        keys[0],
        config.get('TAVILY_SEARCH_DEPTH', 'basic'),
        config.get('TAVILY_MAX_RESULTS', 5),
        config.get('TAVILY_REQUEST_TIMEOUT_SECONDS', 30),
    )

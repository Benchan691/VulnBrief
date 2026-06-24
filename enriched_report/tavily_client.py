import logging
import re
from html.parser import HTMLParser
from urllib.parse import urljoin

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


def _provider_order(config):
    order = config.get('SEARCH_PROVIDER_ORDER') or ['tavily', 'exa', 'searxng']
    if isinstance(order, str):
        order = [item.strip() for item in order.split(',')]
    return [str(item).strip().lower() for item in order if str(item).strip()]


class _TextHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style', 'noscript'}:
            self.skip += 1

    def handle_endtag(self, tag):
        if tag in {'script', 'style', 'noscript'} and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip and data.strip():
            self.parts.append(data.strip())


def _html_to_text(html):
    parser = _TextHTMLParser()
    parser.feed(html or '')
    return re.sub(r'\s+', ' ', ' '.join(parser.parts)).strip()


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


class FailoverSearchClient:
    def __init__(self, clients):
        self.clients = list(clients)
        self.disabled = set()
        if not self.clients:
            raise ValueError('At least one Tavily, Exa, or SearXNG provider must be configured.')

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
    clients = []
    for provider in _provider_order(config):
        if provider == 'tavily':
            clients.extend(
                TavilyClient(
                    key,
                    config.get('TAVILY_SEARCH_DEPTH', 'basic'),
                    config.get('TAVILY_MAX_RESULTS', 5),
                    config.get('TAVILY_REQUEST_TIMEOUT_SECONDS', 30),
                )
                for key in _keys(config, 'TAVILY_API_KEYS', 'TAVILY_API_KEY')
            )
        elif provider == 'exa':
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
        elif provider == 'searxng' and config.get('SEARXNG_BASE_URL'):
            clients.append(
                SearXNGClient(
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
                ),
            )
    return FailoverSearchClient(clients)

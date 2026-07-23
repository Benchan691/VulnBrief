import threading

import requests


def _key_values(value):
    if not value:
        return []
    if isinstance(value, str):
        return [key.strip() for key in value.split(',') if key.strip()]
    return [str(key).strip() for key in value if str(key).strip()]


def _keys(config, list_name, single_name):
    keys = _key_values(config.get(list_name))
    if not keys and config.get(single_name):
        keys = _key_values(config[single_name])
    return keys


class TavilyClient:
    provider = 'tavily'

    def __init__(
        self,
        api_keys,
        search_depth='advanced',
        max_results=8,
        timeout_seconds=30,
        chunks_per_source=3,
        endpoint='https://api.tavily.com/search',
    ):
        self.api_keys = _key_values(api_keys)
        if not self.api_keys:
            raise ValueError('TAVILY_API_KEY must be configured for enriched_weekly reports.')
        self.search_depth = search_depth
        self.max_results = int(max_results)
        self.timeout_seconds = int(timeout_seconds)
        self.chunks_per_source = max(1, int(chunks_per_source or 3))
        self.endpoint = endpoint
        self._key_index = 0
        self._key_lock = threading.Lock()
        self._thread_state = threading.local()

    def _next_key(self):
        previous_key = getattr(self._thread_state, 'last_key', None)
        with self._key_lock:
            for _ in range(len(self.api_keys)):
                key = self.api_keys[self._key_index]
                self._key_index = (self._key_index + 1) % len(self.api_keys)
                if len(self.api_keys) == 1 or key != previous_key:
                    break
        self._thread_state.last_key = key
        return key

    def search(self, query, *, include_domains=None):
        api_key = self._next_key()
        payload = {
            'api_key': api_key,
            'query': query,
            'search_depth': self.search_depth,
            'max_results': self.max_results,
            'include_raw_content': True,
        }
        if self.search_depth == 'advanced':
            payload['chunks_per_source'] = self.chunks_per_source
        domains = [
            str(item).strip()
            for item in (include_domains or [])
            if str(item).strip()
        ]
        if domains:
            payload['include_domains'] = domains
        response = requests.post(
            self.endpoint,
            headers={'Authorization': f'Bearer {api_key}'},
            json=payload,
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json().get('results') or []


def build_search_client(config):
    api_keys = _keys(config, 'TAVILY_API_KEYS', 'TAVILY_API_KEY')
    if not api_keys:
        raise ValueError('TAVILY_API_KEYS or TAVILY_API_KEY must be configured for enriched_weekly reports.')
    return TavilyClient(
        api_keys,
        config.get('TAVILY_SEARCH_DEPTH', 'advanced'),
        config.get('TAVILY_MAX_RESULTS', 8),
        config.get('TAVILY_REQUEST_TIMEOUT_SECONDS', 30),
        config.get('TAVILY_CHUNKS_PER_SOURCE', 3),
    )

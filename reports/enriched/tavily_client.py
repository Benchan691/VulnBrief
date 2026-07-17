import threading

import requests


def _keys(config, list_name, single_name):
    keys = list(config.get(list_name) or [])
    if not keys and config.get(single_name):
        keys = [config[single_name]]
    return [str(key).strip() for key in keys if str(key).strip()]


class TavilyClient:
    provider = 'tavily'

    def __init__(
        self,
        api_keys,
        search_depth='basic',
        max_results=5,
        timeout_seconds=30,
        endpoint='https://api.tavily.com/search',
    ):
        if isinstance(api_keys, str):
            api_keys = [api_keys]
        self.api_keys = [str(key).strip() for key in api_keys if str(key).strip()]
        if not self.api_keys:
            raise ValueError('TAVILY_API_KEY must be configured for enriched_weekly reports.')
        self.search_depth = search_depth
        self.max_results = int(max_results)
        self.timeout_seconds = int(timeout_seconds)
        self.endpoint = endpoint
        self._key_index = 0
        self._key_lock = threading.Lock()

    def _next_key(self):
        with self._key_lock:
            key = self.api_keys[self._key_index]
            self._key_index = (self._key_index + 1) % len(self.api_keys)
            return key

    def search(self, query):
        api_key = self._next_key()
        response = requests.post(
            self.endpoint,
            headers={'Authorization': f'Bearer {api_key}'},
            json={
                'api_key': api_key,
                'query': query,
                'search_depth': self.search_depth,
                'max_results': self.max_results,
                'include_raw_content': True,
            },
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
        config.get('TAVILY_SEARCH_DEPTH', 'basic'),
        config.get('TAVILY_MAX_RESULTS', 5),
        config.get('TAVILY_REQUEST_TIMEOUT_SECONDS', 30),
    )

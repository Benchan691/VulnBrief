import requests


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


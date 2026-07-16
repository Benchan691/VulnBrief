from reports.enriched.tavily_client import SearXNGClient, TavilyClient, build_search_client


class FakeResponse:
    def __init__(self, body, text=''):
        self.body = body
        self.text = text

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


def test_tavily_client_posts_search_request(monkeypatch):
    calls = []

    def fake_post(url, headers, json, timeout):
        calls.append((url, headers, json, timeout))
        return FakeResponse({
            'results': [{
                'url': 'https://example.com/advisory',
                'title': 'Advisory',
                'content': 'Snippet',
            }],
        })

    monkeypatch.setattr('requests.post', fake_post)

    results = TavilyClient('tavily-key', max_results=3, timeout_seconds=9).search('CVE query')

    url, headers, payload, timeout = calls[0]
    assert url == 'https://api.tavily.com/search'
    assert headers['Authorization'] == 'Bearer tavily-key'
    assert payload['query'] == 'CVE query'
    assert payload['max_results'] == 3
    assert timeout == 9
    assert results == [{
        'url': 'https://example.com/advisory',
        'title': 'Advisory',
        'content': 'Snippet',
    }]


def test_searxng_client_uses_snippet_only_without_page_fetch(monkeypatch):
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append((url, params, headers, timeout))
        return FakeResponse({
            'results': [{
                'url': 'https://example.com/advisory',
                'title': 'Advisory',
                'content': 'Snippet',
                'score': 3,
            }],
        })

    monkeypatch.setattr('requests.get', fake_get)

    results = SearXNGClient('https://search.example', max_results=1, timeout_seconds=7).search('CVE query')

    assert len(calls) == 1
    assert calls[0][0] == 'https://search.example/search'
    assert calls[0][1] == {'q': 'CVE query', 'format': 'json'}
    assert calls[0][3] == 7
    assert results == [{
        'url': 'https://example.com/advisory',
        'title': 'Advisory',
        'snippet': 'Snippet',
        'page_content': 'Snippet',
        'score': 3,
        'source_api': 'searxng',
    }]


def test_searxng_client_skips_empty_snippet(monkeypatch):
    def fake_get(url, params=None, headers=None, timeout=None):
        return FakeResponse({
            'results': [{
                'url': 'https://example.com/advisory',
                'title': 'Advisory',
                'content': '',
                'score': 3,
            }],
        })

    monkeypatch.setattr('requests.get', fake_get)

    results = SearXNGClient('https://search.example').search('CVE query')

    assert results == []


def test_searxng_client_skips_oversized_snippet(monkeypatch):
    def fake_get(url, params=None, headers=None, timeout=None):
        return FakeResponse({
            'results': [{
                'url': 'https://example.com/advisory',
                'title': 'Advisory',
                'content': 'x' * 9,
                'score': 3,
            }],
        })

    monkeypatch.setattr('requests.get', fake_get)

    results = SearXNGClient('https://search.example', max_snippet_chars=8).search('CVE query')

    assert results == []


def test_build_search_client_prefers_searxng_when_configured():
    client = build_search_client({
        'SEARXNG_BASE_URL': 'https://search.example',
        'TAVILY_API_KEYS': ['tavily-key'],
    })

    assert client.provider == 'searxng'


def test_build_search_client_uses_first_tavily_key():
    client = build_search_client({'TAVILY_API_KEYS': ['tavily-a', 'tavily-b']})

    assert client.provider == 'tavily'
    assert client.api_key == 'tavily-a'

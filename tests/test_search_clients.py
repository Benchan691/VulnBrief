from enriched_report import tavily_client
from enriched_report.tavily_client import ExaClient, FailoverSearchClient, SearXNGClient, build_search_client


class FakeResponse:
    def __init__(self, body, text=''):
        self.body = body
        self.text = text

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


def test_exa_client_maps_response_to_search_result(monkeypatch):
    calls = []

    def fake_post(url, headers, json, timeout):
        calls.append((url, headers, json, timeout))
        return FakeResponse({
            'results': [{
                'url': 'https://example.com/advisory',
                'title': 'Advisory',
                'highlights': ['Patch now.'],
                'text': 'Full page text.',
                'score': 0.42,
            }],
        })

    monkeypatch.setattr('requests.post', fake_post)

    results = ExaClient('exa-key', max_results=3, timeout_seconds=9).search('CVE query')

    url, headers, payload, timeout = calls[0]
    assert url == 'https://api.exa.ai/search'
    assert headers['x-api-key'] == 'exa-key'
    assert payload['query'] == 'CVE query'
    assert payload['numResults'] == 3
    assert payload['contents']['text']['maxCharacters'] == 60000
    assert timeout == 9
    assert results == [{
        'url': 'https://example.com/advisory',
        'title': 'Advisory',
        'snippet': 'Patch now.',
        'page_content': 'Full page text.',
        'score': 0.42,
        'source_api': 'exa',
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


def test_build_search_client_uses_configured_provider_order():
    client = build_search_client({
        'SEARCH_PROVIDER_ORDER': ['searxng', 'tavily', 'exa'],
        'SEARXNG_BASE_URL': 'https://search.example',
        'TAVILY_API_KEYS': ['tavily-key'],
        'EXA_API_KEYS': ['exa-key'],
    })

    assert [item.provider for item in client.clients] == ['searxng', 'tavily', 'exa']


def test_failover_search_client_tries_next_provider_and_logs(monkeypatch):
    class BrokenClient:
        provider = 'tavily'

        def search(self, query):
            raise RuntimeError('credit limit exceeded')

    class WorkingClient:
        provider = 'exa'

        def search(self, query):
            return [{'url': 'https://example.com'}]

    log_messages = []

    class FakeLogger:
        def info(self, message, *args):
            log_messages.append(message % args)

        def warning(self, message, *args):
            log_messages.append(message % args)

    monkeypatch.setattr(tavily_client, 'logger', FakeLogger())

    results = FailoverSearchClient([BrokenClient(), WorkingClient()]).search('query')

    assert results == [{'url': 'https://example.com'}]
    assert 'search failed provider=tavily key_index=1 disabled=True error=credit limit exceeded' in log_messages
    assert 'search success provider=exa key_index=2 results=1' in log_messages

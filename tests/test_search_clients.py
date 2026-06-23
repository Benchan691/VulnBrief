from enriched_report import tavily_client
from enriched_report.tavily_client import ExaClient, FailoverSearchClient


class FakeResponse:
    def __init__(self, body):
        self.body = body

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

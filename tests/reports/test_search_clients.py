import threading

import pytest

from reports.enriched.tavily_client import TavilyClient, build_search_client


class FakeResponse:
    def raise_for_status(self):
        pass

    def json(self):
        return {'results': [{'url': 'https://example.com/advisory'}]}


def test_tavily_client_rotates_keys_per_search(monkeypatch):
    keys = []

    def fake_post(_url, headers, json, timeout):
        keys.append((headers['Authorization'], json['api_key'], timeout))
        return FakeResponse()

    monkeypatch.setattr('requests.post', fake_post)
    client = TavilyClient(['tavily-a', 'tavily-b'], timeout_seconds=9)

    client.search('first')
    client.search('second')
    client.search('third')

    assert keys == [
        ('Bearer tavily-a', 'tavily-a', 9),
        ('Bearer tavily-b', 'tavily-b', 9),
        ('Bearer tavily-a', 'tavily-a', 9),
    ]


def test_tavily_client_rotates_keys_safely_with_concurrent_searches(monkeypatch):
    keys = []
    lock = threading.Lock()

    def fake_post(_url, headers, json, timeout):
        with lock:
            keys.append(json['api_key'])
        return FakeResponse()

    monkeypatch.setattr('requests.post', fake_post)
    client = TavilyClient(['tavily-a', 'tavily-b'])
    workers = [threading.Thread(target=client.search, args=(str(index),)) for index in range(20)]

    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert keys.count('tavily-a') == keys.count('tavily-b') == 10


def test_build_search_client_requires_tavily_key():
    with pytest.raises(ValueError, match='TAVILY_API_KEYS'):
        build_search_client({})


def test_build_search_client_uses_all_tavily_keys():
    client = build_search_client({'TAVILY_API_KEYS': ['tavily-a', 'tavily-b']})

    assert client.provider == 'tavily'
    assert client.api_keys == ['tavily-a', 'tavily-b']

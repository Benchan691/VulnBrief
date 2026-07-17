import logging

from reports.enriched.search_executor import execute_pending_search_tasks
from reports.enriched.search_results_cache import (
    lookup_cached_results,
    purge_search_cache,
    search_results_cache_key,
    store_cached_results,
)


import pytest

from app import app


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    return app.test_client()


class FakeSearchCacheCollection:
    def __init__(self):
        self.docs = {}

    def find(self, query):
        query_hash = query.get('query_hash')
        cache_version = query.get('cache_version')
        return [
            doc
            for doc in self.docs.values()
            if doc.get('query_hash') == query_hash and doc.get('cache_version') == cache_version
        ]

    def find_one(self, query):
        return self.docs.get(query.get('cache_key'))

    def update_one(self, query, update, upsert=False):
        key = query.get('cache_key')
        existing = self.docs.get(key, {})
        if upsert and key not in self.docs:
            existing = dict(update.get('$setOnInsert') or {})
        existing.update(update.get('$set') or {})
        if '$inc' in update:
            for field, amount in update['$inc'].items():
                existing[field] = existing.get(field, 0) + amount
        self.docs[key] = existing

    def delete_many(self, query):
        if query:
            return type('Result', (), {'deleted_count': 0})()
        count = len(self.docs)
        self.docs = {}
        return type('Result', (), {'deleted_count': count})()


class FakeTasksCollection:
    def __init__(self, tasks):
        self.tasks = list(tasks)

    def find(self, query):
        return [
            task for task in self.tasks
            if task.get('run_id') == query.get('run_id') and task.get('status') == query.get('status')
        ]

    def update_one(self, query, update):
        for task in self.tasks:
            if task['_id'] == query['_id']:
                task.update(update.get('$set') or {})
                if '$inc' in update:
                    for field, amount in update['$inc'].items():
                        task[field] = task.get(field, 0) + amount


class FakeResultsCollection:
    def __init__(self):
        self.documents = []

    def insert_many(self, documents):
        self.documents.extend(documents)


class FakeDatabase:
    def __init__(self, collections):
        self.collections = collections

    def __getitem__(self, name):
        return self.collections[name]


class TrackingTavilyClient:
    calls = 0

    def search(self, query):
        type(self).calls += 1
        return [{
            'url': 'https://acme.example/advisory',
            'title': 'Advisory',
            'content': 'CVE details',
            'raw_content': 'CVE details and patch info',
            'score': 0.9,
        }]


def _sample_task():
    return {
        '_id': 'task-1',
        'run_id': 'run-a',
        'candidate_id': 'candidate-1',
        'cve_id': 'CVE-2026-7000',
        'task_type': 'enrichment',
        'query': 'CVE-2026-7000 vulnerability advisory',
        'query_hash': 'query-hash-1',
        'status': 'pending',
        'attempts': 0,
    }


def test_search_results_cache_key_is_stable_for_same_query_and_url():
    key_a = search_results_cache_key('hash-1', 'https://acme.example/advisory', 'content-1', '1')
    key_b = search_results_cache_key('hash-1', 'https://acme.example/advisory/', 'content-1', '1')
    assert key_a == key_b


def test_store_and_lookup_cached_results():
    database = FakeDatabase({'search_enrichment_cache': FakeSearchCacheCollection()})
    task = _sample_task()
    documents = [{
        'url': 'https://acme.example/advisory',
        'title': 'Advisory',
        'snippet': 'Snippet',
        'page_content': 'Page content',
        'score': 0.8,
        'source_api': 'tavily',
        'content_hash': 'content-1',
    }]

    store_cached_results(database, task, documents, cache_version='1')
    cached = lookup_cached_results(database, task, cache_version='1')

    assert cached == [documents[0]]


def test_purge_search_cache_deletes_all_entries():
    database = FakeDatabase({'search_enrichment_cache': FakeSearchCacheCollection()})
    task = _sample_task()
    store_cached_results(database, task, [{
        'url': 'https://acme.example/advisory',
        'title': 'Advisory',
        'snippet': 'Snippet',
        'page_content': 'Page content',
        'score': 0.8,
        'source_api': 'tavily',
        'content_hash': 'content-1',
    }], cache_version='1')

    deleted_count = purge_search_cache(database)

    assert deleted_count == 1
    assert database['search_enrichment_cache'].docs == {}


def test_execute_pending_search_tasks_reuses_cached_results_without_calling_tavily(caplog):
    caplog.set_level(logging.INFO, logger='reports.enriched.search_executor')
    TrackingTavilyClient.calls = 0
    task = _sample_task()
    results = FakeResultsCollection()
    database = FakeDatabase({
        'search_enrichment_tasks': FakeTasksCollection([dict(task)]),
        'search_enrichment_results': results,
        'search_enrichment_cache': FakeSearchCacheCollection(),
    })
    store_cached_results(database, task, [{
        'url': 'https://acme.example/advisory',
        'title': 'Cached advisory',
        'snippet': 'Cached snippet',
        'page_content': 'Cached page content',
        'score': 0.7,
        'source_api': 'tavily',
        'content_hash': 'cached-content',
    }], cache_version='1')

    completed = execute_pending_search_tasks(
        database,
        'run-a',
        {
        },
        client=TrackingTavilyClient(),
    )

    tasks_collection = database.collections['search_enrichment_tasks']
    assert completed == 1
    assert TrackingTavilyClient.calls == 0
    assert len(results.documents) == 1
    assert results.documents[0]['run_id'] == 'run-a'
    assert results.documents[0]['title'] == 'Cached advisory'
    assert tasks_collection.tasks[0]['status'] == 'completed'
    assert 'enriched search cache hit cve=CVE-2026-7000 task_type=enrichment results=1' in caplog.text


def test_execute_pending_search_tasks_stores_results_for_reuse_on_miss():
    TrackingTavilyClient.calls = 0
    task = _sample_task()
    results = FakeResultsCollection()
    cache = FakeSearchCacheCollection()
    database = FakeDatabase({
        'search_enrichment_tasks': FakeTasksCollection([dict(task)]),
        'search_enrichment_results': results,
        'search_enrichment_cache': cache,
    })

    completed = execute_pending_search_tasks(
        database,
        'run-a',
        {
            'TAVILY_API_KEY': 'fake',
        },
        client=TrackingTavilyClient(),
    )

    assert completed == 1
    assert TrackingTavilyClient.calls == 1
    assert len(results.documents) == 1
    assert len(cache.docs) == 1

    TrackingTavilyClient.calls = 0
    second_task = dict(task)
    second_task.update({'_id': 'task-2', 'run_id': 'run-b', 'status': 'pending'})
    second_results = FakeResultsCollection()
    second_database = FakeDatabase({
        'search_enrichment_tasks': FakeTasksCollection([second_task]),
        'search_enrichment_results': second_results,
        'search_enrichment_cache': cache,
    })

    execute_pending_search_tasks(
        second_database,
        'run-b',
        {
        },
        client=TrackingTavilyClient(),
    )

    assert TrackingTavilyClient.calls == 0
    assert len(second_results.documents) == 1
    assert second_results.documents[0]['run_id'] == 'run-b'


def test_execute_pending_search_tasks_does_not_compress_tavily_page_content():
    task = _sample_task()
    results = FakeResultsCollection()
    database = FakeDatabase({
        'search_enrichment_tasks': FakeTasksCollection([dict(task)]),
        'search_enrichment_results': results,
        'search_enrichment_cache': FakeSearchCacheCollection(),
    })

    execute_pending_search_tasks(
        database,
        'run-a',
        {},
        client=TrackingTavilyClient(),
    )

    assert results.documents[0]['page_content'] == 'CVE details and patch info'


def test_purge_search_cache_route(client, monkeypatch):
    with client.session_transaction() as session:
        session['username'] = 'test-user'

    cache = FakeSearchCacheCollection()
    database = FakeDatabase({'search_enrichment_cache': cache})
    store_cached_results(database, _sample_task(), [{
        'url': 'https://acme.example/advisory',
        'title': 'Advisory',
        'snippet': 'Snippet',
        'page_content': 'Page content',
        'score': 0.8,
        'source_api': 'tavily',
        'content_hash': 'content-1',
    }], cache_version='1')
    monkeypatch.setattr('reports.routes.get_web_database', lambda: database)

    response = client.post('/api/reports/search-cache/purge')

    assert response.status_code == 200
    assert response.get_json()['deleted_count'] == 1
    assert cache.docs == {}

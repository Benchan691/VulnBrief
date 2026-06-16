import pytest
from bson import json_util
from pymongo.errors import ServerSelectionTimeoutError

from app import app


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    return app.test_client()


def authenticate(client):
    with client.session_transaction() as session:
        session['username'] = 'test-user'


def test_review_pages_require_authentication(client):
    assert client.get('/reviews').status_code == 302
    response = client.get('/api/reviews')
    assert response.status_code == 401
    assert response.get_json()['error'] == 'Authentication required'
    assert client.get('/api/reviews/search?search=CVE').status_code == 401
    assert client.put('/api/subscriptions/test@example.com', json={}).status_code == 401
    assert client.post('/api/reviews/export-json', json={}).status_code == 401


def test_review_collection_discovery_and_invalid_collection(client):
    authenticate(client)

    response = client.get('/api/reviews')
    assert response.status_code == 200
    names = {item['name'] for item in response.get_json()['data']}
    assert {'avd_review', 'hkcert_review', 'cve_review'} <= names

    assert client.get('/api/reviews/not_a_review').status_code == 404


def test_review_document_filtering_and_pagination(client):
    authenticate(client)

    response = client.get('/api/reviews/hkcert_review?page=1&page_size=1')
    assert response.status_code == 200
    body = response.get_json()
    assert body['page'] == 1
    assert body['page_size'] == 1
    assert len(body['data']) <= 1
    assert body['total'] >= len(body['data'])
    assert isinstance(body['data'][0]['selection_id'], str)
    assert '_id' not in body['data'][0]['document']

    filtered = client.get('/api/reviews/hkcert_review?code=CVE-')
    assert filtered.status_code == 200
    for item in filtered.get_json()['data']:
        document = item['document']
        assert 'CVE-' in (document.get('code') or document.get('cve') or '')


def test_review_collection_page_renders(client):
    authenticate(client)

    main_page = client.get('/reviews')
    assert main_page.status_code == 200
    assert b'Global search' in main_page.data
    assert b'Combined Results' in main_page.data

    response = client.get('/reviews/avd_review')
    assert response.status_code == 200
    assert b'avd_review' in response.data
    assert b'Click View to inspect' in response.data
    assert b'Clear Selection' in response.data


def test_original_document_export_preserves_order(client):
    authenticate(client)
    first = client.get('/api/reviews/avd_review?page_size=1').get_json()['data'][0]
    second = client.get('/api/reviews/hkcert_review?page_size=1').get_json()['data'][0]

    response = client.post('/api/reviews/export-json', json={
        'selections': [
            {'collection': 'hkcert_review', 'selection_id': second['selection_id']},
            {'collection': 'avd_review', 'selection_id': first['selection_id']},
        ],
    })

    assert response.status_code == 200
    assert response.mimetype == 'application/json'
    assert 'attachment; filename="vulnerability-export-' in response.headers['Content-Disposition']
    documents = json_util.loads(response.data.decode('utf-8'))
    assert [document['_id'] for document in documents] == [
        second['selection_id'],
        first['selection_id'],
    ]
    assert all('details' in document and 'source' in document for document in documents)


def test_global_review_search_orders_by_scraped_at(client, monkeypatch):
    authenticate(client)
    views = {
        'b_review': {'options': {'viewOn': 'b', 'pipeline': [{'$project': {'title': 1}}]}},
        'a_review': {'options': {'viewOn': 'a', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    documents = {
        'a_review': [
            {'_id': 'a:1', 'title': 'Older A', 'scraped_at': '2026-06-01T00:00:00+00:00'},
            {'_id': 'a:2', 'title': 'Newer A', 'scraped_at': '2026-06-10T00:00:00+00:00'},
        ],
        'b_review': [
            {'_id': 'b:1', 'title': 'Newest B', 'scraped_at': '2026-06-15T00:00:00+00:00'},
            {'_id': 'b:2', 'title': 'Middle B', 'scraped_at': '2026-06-05T00:00:00+00:00'},
        ],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    def query_matches(database, view, mongo_filter, config):
        name = next(name for name, candidate in views.items() if candidate is view)
        selected = [dict(document) for document in documents[name]]
        return len(documents[name]), selected

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    monkeypatch.setattr('routes.review._query_review_matches', query_matches)

    response = client.get('/api/reviews/search?title=test&page=1&page_size=2')
    assert response.status_code == 200
    body = response.get_json()
    assert body['total'] == 4
    assert body['pages'] == 2
    assert [item['selection_id'] for item in body['data']] == ['b:1', 'a:2']

    response = client.get('/api/reviews/search?title=test&page=2&page_size=2')
    assert response.status_code == 200
    body = response.get_json()
    assert [item['selection_id'] for item in body['data']] == ['b:2', 'a:1']

    response = client.get('/api/reviews/search?collection=a_review&page_size=1')
    assert response.status_code == 200
    assert response.get_json()['total'] == 2


def test_global_review_search_orders_by_preprocessing_priority(client, monkeypatch):
    authenticate(client)
    views = {
        'low_review': {'options': {'viewOn': 'low', 'pipeline': [{'$project': {'title': 1}}]}},
        'high_review': {'options': {'viewOn': 'high', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    documents = {
        'low_review': [
            {
                '_id': 'low:1',
                'title': 'Newer low priority',
                'scraped_at': '2026-06-15T00:00:00+00:00',
            },
        ],
        'high_review': [
            {
                '_id': 'high:1',
                'title': 'Older high priority',
                'scraped_at': '2026-06-01T00:00:00+00:00',
            },
        ],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    def query_matches(database, view, mongo_filter, config):
        name = next(name for name, candidate in views.items() if candidate is view)
        selected = [dict(document) for document in documents[name]]
        return len(documents[name]), selected

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    monkeypatch.setattr('routes.review._query_review_matches', query_matches)
    app.config['PREPROCESSING_PRIORITIES'] = {
        'default': 1,
        'collections': {'high': 9, 'low': 1},
        'field_boosts': {},
    }

    response = client.get('/api/reviews/search?title=test&page=1&page_size=2')
    assert response.status_code == 200
    body = response.get_json()
    assert body['total'] == 2
    assert [item['selection_id'] for item in body['data']] == ['high:1', 'low:1']


def test_review_documents_sort_newest_first(client, monkeypatch):
    authenticate(client)
    view = {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}}
    captured = {}

    class FakeCollection:
        def aggregate(self, pipeline):
            captured['pipeline'] = pipeline
            return iter([{
                'documents': [
                    {'_id': 'cve:2', 'title': 'Newer', 'scraped_at': '2026-06-10T00:00:00+00:00'},
                ],
                'metadata': [{'total': 2}],
            }])

    class FakeDatabase:
        def __getitem__(self, name):
            return FakeCollection()

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: {'cve_review': view})

    response = client.get('/api/reviews/cve_review?page_size=1')
    assert response.status_code == 200
    assert response.get_json()['data'][0]['selection_id'] == 'cve:2'
    assert {'$sort': {'scraped_at': -1, '_id': -1}} in captured['pipeline']


def test_global_review_search_rejects_empty_and_invalid_filters(client, monkeypatch):
    authenticate(client)
    assert client.get('/api/reviews/search').status_code == 400

    monkeypatch.setattr('routes.review._review_views', lambda database: {})
    response = client.get('/api/reviews/search?collection=not_a_review')
    assert response.status_code == 400
    assert 'not found' in response.get_json()['error']


@pytest.mark.parametrize('payload, status', [
    ({}, 400),
    ({'selections': []}, 400),
    ({'selections': [{'collection': 'not_a_review', 'selection_id': 'x'}]}, 400),
    ({'selections': [{'collection': 'avd_review', 'selection_id': 'missing'}]}, 404),
])
def test_original_document_export_rejects_invalid_selections(client, payload, status):
    authenticate(client)
    assert client.post('/api/reviews/export-json', json=payload).status_code == status


def test_review_api_handles_database_failure(client, monkeypatch):
    authenticate(client)

    def unavailable_database():
        raise ServerSelectionTimeoutError('unavailable')

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', unavailable_database)
    response = client.get('/api/reviews')
    assert response.status_code == 503
    assert 'Unable to connect' in response.get_json()['error']
    response = client.post('/api/reviews/export-json', json={
        'selections': [{'collection': 'avd_review', 'selection_id': 'avd:1'}],
    })
    assert response.status_code == 503
    response = client.get('/api/reviews/search?search=CVE')
    assert response.status_code == 503

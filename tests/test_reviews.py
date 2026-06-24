import re

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


def _nested_value(document, field):
    value = document
    for part in field.split('.'):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _document_matches_mongo_filter(document, mongo_filter):
    if not mongo_filter:
        return True
    if '$and' in mongo_filter:
        return all(
            _document_matches_mongo_filter(document, clause)
            for clause in mongo_filter['$and']
        )
    if '$or' in mongo_filter:
        return any(
            _document_matches_mongo_filter(document, clause)
            for clause in mongo_filter['$or']
        )

    for field, condition in mongo_filter.items():
        if field.startswith('$'):
            continue
        value = _nested_value(document, field)
        if isinstance(condition, dict):
            if '$regex' in condition:
                pattern = condition['$regex']
                flags = re.IGNORECASE if condition.get('$options') == 'i' else 0
                haystack = value if isinstance(value, str) else str(value or '')
                if isinstance(value, list):
                    haystack = ' '.join(str(item) for item in value)
                if not re.search(pattern, haystack, flags):
                    return False
            if '$gte' in condition and (document.get(field) or '') < condition['$gte']:
                return False
            if '$lt' in condition and (document.get(field) or '') >= condition['$lt']:
                return False
        elif value != condition:
            return False
    return True


def patch_iter_collection_documents(monkeypatch, views, documents=None, on_query=None):
    documents = documents or {}

    def iter_collection_documents(database, view, mongo_filter):
        if on_query is not None:
            on_query(view, mongo_filter)
        name = next(view_name for view_name, candidate in views.items() if candidate is view)
        sorted_documents = sorted(
            documents.get(name, []),
            key=lambda document: (
                document.get('scraped_at') or '',
                str(document.get('_id', '')),
            ),
            reverse=True,
        )
        for document in sorted_documents:
            if _document_matches_mongo_filter(document, mongo_filter):
                yield dict(document)

    monkeypatch.setattr('routes.review._iter_collection_documents', iter_collection_documents)


def patch_query_review_slice(monkeypatch, views, documents=None, on_query=None):
    documents = documents or {}

    def query_review_slice(database, view, mongo_filter, skip, limit):
        if on_query is not None:
            on_query(view, mongo_filter)
        name = next(view_name for view_name, candidate in views.items() if candidate is view)
        sorted_documents = sorted(
            documents.get(name, []),
            key=lambda document: (
                document.get('scraped_at') or '',
                str(document.get('_id', '')),
            ),
            reverse=True,
        )
        filtered = [
            dict(document)
            for document in sorted_documents
            if _document_matches_mongo_filter(document, mongo_filter)
        ]
        return len(filtered), filtered[skip:skip + limit]

    monkeypatch.setattr('routes.review._query_review_slice', query_review_slice)


def patch_cve_search_data(monkeypatch, views, documents=None, on_query=None):
    documents = documents or {}
    cve_view_names = sorted(
        name for name, view in views.items()
        if view['options']['viewOn'] == 'cve'
    )
    if len(documents) <= 1 and len(cve_view_names) == 1:
        if not documents:
            documents = {cve_view_names[0]: []}
        patch_query_review_slice(monkeypatch, views, documents, on_query=on_query)
        return
    patch_iter_collection_documents(monkeypatch, views, documents, on_query=on_query)


def test_review_pages_require_authentication(client):
    assert client.get('/reviews').status_code == 302
    response = client.get('/api/reviews')
    assert response.status_code == 401
    assert response.get_json()['error'] == 'Authentication required'
    assert client.get('/api/reviews/search?search=CVE').status_code == 401
    assert client.post('/api/reports/evidence-cache/purge').status_code == 401
    assert client.post('/api/reports/search-cache/purge').status_code == 401
    assert client.put('/api/subscriptions/test@example.com', json={}).status_code == 401
    assert client.post('/api/reviews/export-json', json={}).status_code == 401
    assert client.post('/api/reviews/auto-select', json={}).status_code == 401


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
        values = []
        for field in ('code', 'cve', 'cve_code', 'cve_codes'):
            value = document.get(field)
            if isinstance(value, list):
                values.extend(str(entry) for entry in value)
            elif value not in (None, ''):
                values.append(str(value))
        assert any('CVE-' in value for value in values)


def test_review_collection_page_renders(client):
    authenticate(client)

    main_page = client.get('/reviews')
    assert main_page.status_code == 200
    assert b'CVE Results' in main_page.data
    assert b'Vendor' in main_page.data
    assert b'Review type' not in main_page.data
    assert b'Auto Select Best' not in main_page.data
    assert b'By importance' in main_page.data

    response = client.get('/reviews/avd_review')
    assert response.status_code == 200
    assert b'avd_review' in response.data
    assert b'Click View to inspect' in response.data
    assert b'Clear Selection' in response.data


def test_review_search_includes_selection_score(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    documents = {
        'cve_review': [{
            '_id': 'cve:1',
            'code': 'CVE-2026-5001',
            'severity': 'High',
            'summary': 'Remote code execution exploited in the wild.',
            'scraped_at': '2026-06-20T00:00:00+00:00',
        }],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_cve_search_data(monkeypatch, views, documents)
    monkeypatch.setattr('routes.review._attach_related_cve_documents', lambda *args: None)

    response = client.get('/api/reviews/search?mode=cve')
    assert response.status_code == 200
    item = response.get_json()['data'][0]
    assert 'selection_score' in item
    assert 'patch_priority' in item
    assert item['selection_score'] > 0


def test_auto_select_returns_top_records_by_score(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    documents = {
        'cve_review': [
            {
                '_id': 'low:1',
                'code': 'CVE-2026-0001',
                'severity': 'Low',
                'summary': 'Minor issue.',
                'scraped_at': '2026-06-01T00:00:00+00:00',
            },
            {
                '_id': 'high:1',
                'code': 'CVE-2026-0002',
                'severity': 'Critical',
                'cisa_kev': True,
                'summary': 'Remote code execution exploited in the wild.',
                'scraped_at': '2026-06-20T00:00:00+00:00',
                'containers': {
                    'cna': {
                        'metrics': [{'cvssV3_1': {'baseSeverity': 'CRITICAL', 'baseScore': 9.8}}],
                    },
                },
            },
            {
                '_id': 'medium:1',
                'code': 'CVE-2026-0003',
                'severity': 'Medium',
                'summary': 'Privilege escalation proof of concept available.',
                'scraped_at': '2026-06-15T00:00:00+00:00',
            },
        ],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_iter_collection_documents(monkeypatch, views, documents)

    response = client.post('/api/reviews/auto-select', json={'count': 2})
    assert response.status_code == 200
    body = response.get_json()
    assert body['matched'] == 3
    assert body['selected'] == 2
    assert [item['selection_id'] for item in body['selections']] == ['high:1', 'medium:1']
    assert body['selections'][0]['selection_score'] >= body['selections'][1]['selection_score']
    assert body['summary']['Critical'] == 1


def test_auto_select_respects_severity_filters_and_sorts_by_score(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    documents = {
        'cve_review': [
            {
                '_id': 'low:1',
                'code': 'CVE-2026-0001',
                'severity': 'Low',
                'summary': 'Minor issue.',
                'scraped_at': '2026-06-01T00:00:00+00:00',
            },
            {
                '_id': 'high:1',
                'code': 'CVE-2026-0002',
                'severity': 'Critical',
                'cisa_kev': True,
                'summary': 'Remote code execution exploited in the wild.',
                'scraped_at': '2026-06-20T00:00:00+00:00',
                'containers': {
                    'cna': {
                        'metrics': [{'cvssV3_1': {'baseSeverity': 'CRITICAL', 'baseScore': 9.8}}],
                    },
                },
            },
            {
                '_id': 'medium:1',
                'code': 'CVE-2026-0003',
                'severity': 'Medium',
                'summary': 'Privilege escalation proof of concept available.',
                'scraped_at': '2026-06-15T00:00:00+00:00',
            },
        ],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_iter_collection_documents(monkeypatch, views, documents)

    response = client.post('/api/reviews/auto-select', json={
        'count': 2,
        'mode': 'cve',
        'status': ['Critical', 'Medium'],
    })
    assert response.status_code == 200
    body = response.get_json()
    assert body['matched'] == 2
    assert body['selected'] == 2
    assert [item['selection_id'] for item in body['selections']] == ['high:1', 'medium:1']
    assert body['selections'][0]['selection_score'] >= body['selections'][1]['selection_score']


@pytest.mark.parametrize('count, status', [
    (0, 400),
    (501, 400),
])
def test_auto_select_rejects_invalid_count(client, count, status):
    authenticate(client)
    response = client.post('/api/reviews/auto-select', json={'count': count})
    assert response.status_code == status


def test_auto_select_rejects_scan_over_limit(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    documents = {
        'cve_review': [
            {
                '_id': f'cve:{index}',
                'code': f'CVE-2026-{index:04d}',
                'severity': 'Low',
                'summary': 'Minor issue.',
                'scraped_at': '2026-06-01T00:00:00+00:00',
            }
            for index in range(3)
        ],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    monkeypatch.setattr('routes.review.AUTO_SELECT_SCAN_LIMIT', 2)
    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_iter_collection_documents(monkeypatch, views, documents)

    response = client.post('/api/reviews/auto-select', json={'count': 1})
    assert response.status_code == 400
    assert 'scan limit' in response.get_json()['error']


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
        'cve_b_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
        'cve_a_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
        'cve_high_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
        'cve_low_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    documents = {
        'cve_a_review': [
            {'_id': 'a:1', 'title': 'Older A', 'scraped_at': '2026-06-01T00:00:00+00:00'},
            {'_id': 'a:2', 'title': 'Newer A', 'scraped_at': '2026-06-10T00:00:00+00:00'},
        ],
        'cve_b_review': [
            {'_id': 'b:1', 'title': 'Newest B', 'scraped_at': '2026-06-15T00:00:00+00:00'},
            {'_id': 'b:2', 'title': 'Middle B', 'scraped_at': '2026-06-05T00:00:00+00:00'},
        ],
        'cve_high_review': [
            {
                '_id': 'high:1',
                'title': 'Older high priority',
                'scraped_at': '2026-06-02T00:00:00+00:00',
            },
        ],
        'cve_low_review': [
            {
                '_id': 'low:1',
                'title': 'Newer low priority',
                'scraped_at': '2026-06-12T00:00:00+00:00',
            },
        ],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_iter_collection_documents(monkeypatch, views, documents)

    response = client.get('/api/reviews/search?mode=cve&page=1&page_size=3')
    assert response.status_code == 200
    body = response.get_json()
    assert body['total'] == 6
    assert body['pages'] == 2
    assert [item['selection_id'] for item in body['data']] == ['b:1', 'low:1', 'a:2']

    response = client.get('/api/reviews/search?mode=cve&page=2&page_size=3')
    assert response.status_code == 200
    body = response.get_json()
    assert [item['selection_id'] for item in body['data']] == ['b:2', 'high:1', 'a:1']


def test_review_search_mode_cve_uses_cve_review_only(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
        'avd_review': {'options': {'viewOn': 'avd', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    captured = []

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    def on_query(view, mongo_filter):
        captured.append(view['options']['viewOn'])

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_cve_search_data(monkeypatch, views, on_query=on_query)
    monkeypatch.setattr('routes.review._attach_related_cve_documents', lambda *args: None)

    response = client.get('/api/reviews/search?mode=cve')
    assert response.status_code == 200
    assert captured == ['cve']


def test_review_search_accepts_multiple_severity_filters(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    documents = {
        'cve_review': [
            {'_id': 'critical:1', 'code': 'CVE-2026-0001', 'severity': 'Critical', 'scraped_at': '2026-06-10T00:00:00+00:00'},
            {'_id': 'high:1', 'code': 'CVE-2026-0002', 'severity': 'High', 'scraped_at': '2026-06-09T00:00:00+00:00'},
            {'_id': 'low:1', 'code': 'CVE-2026-0003', 'severity': 'Low', 'scraped_at': '2026-06-08T00:00:00+00:00'},
        ],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_cve_search_data(monkeypatch, views, documents)
    monkeypatch.setattr('routes.review._attach_related_cve_documents', lambda *args: None)

    response = client.get('/api/reviews/search?mode=cve&status=Critical&status=High')
    assert response.status_code == 200
    assert [item['selection_id'] for item in response.get_json()['data']] == ['critical:1', 'high:1']


def test_review_search_rejects_non_cve_mode(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
        'avd_review': {'options': {'viewOn': 'avd', 'pipeline': [{'$project': {'title': 1}}]}},
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)

    response = client.get('/api/reviews/search?mode=non_cve')
    assert response.status_code == 400
    assert 'Only CVE review documents are supported' in response.get_json()['error']


def test_review_search_mode_cve_includes_classification(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    documents = {
        'cve_review': [
            {
                '_id': 'cve:1',
                'scraped_at': '2026-06-18T12:00:00',
                'title': 'Unclassified CVE',
                'classification': {'status': 'unclassified', 'best_vendor': 'Microsoft'},
            },
            {
                '_id': 'cve:2',
                'scraped_at': '2026-06-17T12:00:00',
                'title': 'Classified CVE',
                'classification': {
                    'status': 'classified',
                    'vendor': 'Red Hat',
                    'product': 'Enterprise Linux',
                },
            },
        ],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_cve_search_data(monkeypatch, views, documents)
    monkeypatch.setattr('routes.review._attach_related_cve_documents', lambda *args: None)

    response = client.get('/api/reviews/search?mode=cve&page_size=10')
    assert response.status_code == 200
    data = response.get_json()['data']
    assert data[0]['document']['classification']['status'] == 'unclassified'
    assert data[1]['document']['classification']['vendor'] == 'Red Hat'
    assert data[1]['document']['classification']['product'] == 'Enterprise Linux'


def test_review_search_mode_cve_includes_related_records(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
        'avd_review': {'options': {'viewOn': 'avd', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    cve_document = {
        '_id': 'cve:CVE-2026-1000',
        'code': 'CVE-2026-1000',
        'title': 'Primary CVE',
        'severity': 'High',
    }
    related_avd = {
        '_id': 'avd:CVE-2026-1000',
        'code': '2026-1000',
        'title': 'Related AVD',
        'severity': 'Medium',
    }
    related_filters = []

    documents = {
        'cve_review': [{
            **cve_document,
            'scraped_at': '2026-06-18T00:00:00+00:00',
        }],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    def query_slice(database, view, mongo_filter, skip, limit):
        source = view['options']['viewOn']
        filter_text = str(mongo_filter)
        is_related_query = '^' in filter_text and '2026' in filter_text
        if is_related_query:
            related_filters.append(filter_text)
            if source == 'cve':
                return 1, [dict(cve_document)]
            if source == 'avd':
                return 1, [dict(related_avd)]
            return 0, []
        if source == 'cve':
            filtered = [
                dict(document)
                for document in documents['cve_review']
                if _document_matches_mongo_filter(document, mongo_filter)
            ]
            return len(filtered), filtered[skip:skip + limit]
        return 0, []

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    monkeypatch.setattr('routes.review._query_review_slice', query_slice)

    response = client.get('/api/reviews/search?mode=cve&search=CVE-2026-1000')
    assert response.status_code == 200
    item = response.get_json()['data'][0]
    related = item['related']
    assert {entry['collection'] for entry in related} == {'cve_review', 'avd_review'}
    assert any(entry['code'] == '2026-1000' for entry in related)
    assert any(entry['is_self'] for entry in related)
    assert any('CVE\\\\-2026\\\\-1000' in filter_text for filter_text in related_filters)
    assert any('2026\\\\-1000' in filter_text for filter_text in related_filters)
    assert any(entry.get('document', {}).get('code') == '2026-1000' for entry in related)
    assert {
        'collection', 'selection_id', 'document', 'code', 'title', 'severity', 'affected', 'is_self',
    } <= set(related[0])


def test_review_extracts_multiple_cves_from_hkcert_identifiers_and_cve_codes():
    from routes.review import _extract_cve_codes, _related_cve_mongo_filter

    document = {
        'cve_codes': ['2026-1000'],
        'details': {
            'hkcert': {
                'vulnerability_identifiers': [
                    {'cve_id': 'CVE-2026-2000'},
                    {'cve_id': 'CVE-2026-1000'},
                ]
            }
        },
    }

    assert _extract_cve_codes(document) == ['CVE-2026-1000', 'CVE-2026-2000']
    related_filter = str(_related_cve_mongo_filter(['CVE-2026-1000']))
    assert 'cve_codes' in related_filter
    assert 'details.hkcert.vulnerability_identifiers.cve_id' in related_filter


def test_review_search_keyword_matches_nested_projected_details(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    captured = []

    documents = {
        'cve_review': [
            {
                '_id': 'cve:1',
                'code': 'CVE-2026-1000',
                'title': 'Summary misses keyword',
                'severity': 'High',
                'details': {'source': {'description': 'contains nested-only-token'}},
            },
            {
                '_id': 'cve:2',
                'code': 'CVE-2026-2000',
                'title': 'Another record',
                'severity': 'High',
                'details': {'source': {'description': 'different text'}},
            },
        ],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    def on_query(view, mongo_filter):
        captured.append(mongo_filter)

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_cve_search_data(monkeypatch, views, documents, on_query=on_query)
    monkeypatch.setattr('routes.review._attach_related_cve_documents', lambda *args: None)

    response = client.get('/api/reviews/search?mode=cve&search=nested-only-token')

    assert response.status_code == 200
    body = response.get_json()
    assert body['total'] == 1
    assert body['data'][0]['selection_id'] == 'cve:1'
    assert 'details.source.description' in str(captured[0])


def test_review_search_keyword_matches_any_term(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    documents = {
        'cve_review': [
            {
                '_id': 'cve:cisco',
                'title': 'Cisco issue',
                'severity': 'High',
                'scraped_at': '2026-06-10T00:00:00+00:00',
                'classification': {'status': 'classified', 'best_vendor': 'Cisco'},
            },
            {
                '_id': 'cve:microsoft',
                'title': 'Microsoft issue',
                'severity': 'High',
                'scraped_at': '2026-06-09T00:00:00+00:00',
                'classification': {
                    'status': 'classified',
                    'best_vendor': 'Microsoft',
                    'best_product': 'Exchange Server',
                },
            },
            {
                '_id': 'cve:other',
                'title': 'Unrelated issue',
                'severity': 'High',
                'scraped_at': '2026-06-08T00:00:00+00:00',
                'classification': {'status': 'classified', 'best_vendor': 'Apache'},
            },
        ],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_cve_search_data(monkeypatch, views, documents)
    monkeypatch.setattr('routes.review._attach_related_cve_documents', lambda *args: None)

    response = client.get('/api/reviews/search?mode=cve&search=cisco%20microsoft')

    assert response.status_code == 200
    body = response.get_json()
    assert body['total'] == 2
    assert {item['selection_id'] for item in body['data']} == {'cve:cisco', 'cve:microsoft'}


def test_review_search_keyword_matches_classification_fields(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    documents = {
        'cve_review': [
            {
                '_id': 'cve:1',
                'title': 'Generic CVE',
                'severity': 'High',
                'scraped_at': '2026-06-10T00:00:00+00:00',
                'classification': {
                    'status': 'classified',
                    'best_vendor': 'Microsoft',
                    'best_product': 'Exchange Server',
                },
            },
        ],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_cve_search_data(monkeypatch, views, documents)
    monkeypatch.setattr('routes.review._attach_related_cve_documents', lambda *args: None)

    response = client.get('/api/reviews/search?mode=cve&search=exchange')

    assert response.status_code == 200
    body = response.get_json()
    assert body['total'] == 1
    assert body['data'][0]['selection_id'] == 'cve:1'


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


def test_global_review_search_allows_empty_filters_and_rejects_invalid_filters(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_cve_search_data(
        monkeypatch,
        views,
        {'cve_review': [{'_id': 'cve:1', 'title': 'Example'}]},
    )

    response = client.get('/api/reviews/search')
    assert response.status_code == 200
    assert response.get_json()['total'] == 1

    response = client.get('/api/reviews/search?mode=non_cve')
    assert response.status_code == 400
    assert 'Only CVE review documents are supported' in response.get_json()['error']

    monkeypatch.setattr('routes.review._review_views', lambda database: {})
    response = client.get('/api/reviews/search')
    assert response.status_code == 200
    assert response.get_json()['total'] == 0

    response = client.get('/api/reviews/search?status=Invalid')
    assert response.status_code == 400
    assert 'Severity' in response.get_json()['error']


def test_review_severity_filter_applies_known_only_by_default(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    captured = []

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    def on_query(view, mongo_filter):
        captured.append(mongo_filter)

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_cve_search_data(monkeypatch, views, on_query=on_query)

    response = client.get('/api/reviews/search?collection=cve_review&title=test')
    assert response.status_code == 200
    assert 'severity' in str(captured[0])

    captured.clear()
    response = client.get('/api/reviews/search?collection=cve_review')
    assert response.status_code == 200
    assert captured == [{}]

    captured.clear()
    response = client.get('/api/reviews/search?collection=cve_review&include_unknown=true')
    assert response.status_code == 200
    assert captured == [{}]

    captured.clear()
    response = client.get('/api/reviews/search?collection=cve_review&status=High&include_unknown=true')
    assert response.status_code == 200
    assert '$or' in captured[0]


def test_review_search_scrape_time_filter_applies_to_query(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    captured = []

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    def on_query(view, mongo_filter):
        captured.append(mongo_filter)

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_cve_search_data(monkeypatch, views, on_query=on_query)

    response = client.get(
        '/api/reviews/search?mode=cve&time_window=custom'
        '&start=2026-06-01T08:30&end=2026-06-02T09:45',
    )

    assert response.status_code == 200
    assert captured == [{
        'scraped_at': {
            '$gte': '2026-06-01T00:30:00+00:00',
            '$lt': '2026-06-02T01:45:00+00:00',
        },
    }]


def test_review_search_rejects_invalid_scrape_time_filter(client):
    authenticate(client)

    response = client.get(
        '/api/reviews/search?mode=cve&time_window=custom'
        '&start=2026-06-03T00:00&end=2026-06-02T00:00',
    )

    assert response.status_code == 400
    assert 'scrape time' in response.get_json()['error']


def test_global_review_search_allows_over_export_limit(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    documents = {
        'cve_review': [
            {
                '_id': f'cve:{index}',
                'title': f'CVE {index}',
                'scraped_at': f'2026-06-{index % 28 + 1:02d}T00:00:00+00:00',
            }
            for index in range(3)
        ],
    }

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    monkeypatch.setattr('routes.review.MAX_EXPORT_SELECTIONS', 2)
    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_cve_search_data(monkeypatch, views, documents)

    response = client.get('/api/reviews/search?mode=cve')

    assert response.status_code == 200
    assert response.get_json()['total'] == 3


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

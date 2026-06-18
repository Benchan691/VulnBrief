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
            yield dict(document)

    monkeypatch.setattr('routes.review._iter_collection_documents', iter_collection_documents)


def test_review_pages_require_authentication(client):
    assert client.get('/reviews').status_code == 302
    response = client.get('/api/reviews')
    assert response.status_code == 401
    assert response.get_json()['error'] == 'Authentication required'
    assert client.get('/api/reviews/search?search=CVE').status_code == 401
    assert client.get('/api/reviews/auto-select-best?search=CVE').status_code == 401
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
    assert b'Review type' in main_page.data
    assert b'CVE Results' in main_page.data
    assert b'Vendor' in main_page.data
    assert b'Auto Select Best' in main_page.data

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
        'high_review': {'options': {'viewOn': 'high', 'pipeline': [{'$project': {'title': 1}}]}},
        'low_review': {'options': {'viewOn': 'low', 'pipeline': [{'$project': {'title': 1}}]}},
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
        'high_review': [
            {
                '_id': 'high:1',
                'title': 'Older high priority',
                'scraped_at': '2026-06-02T00:00:00+00:00',
            },
        ],
        'low_review': [
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

    response = client.get('/api/reviews/search?title=test&page=1&page_size=3')
    assert response.status_code == 200
    body = response.get_json()
    assert body['total'] == 6
    assert body['pages'] == 2
    assert [item['selection_id'] for item in body['data']] == ['b:1', 'low:1', 'a:2']

    response = client.get('/api/reviews/search?title=test&page=2&page_size=3')
    assert response.status_code == 200
    body = response.get_json()
    assert [item['selection_id'] for item in body['data']] == ['b:2', 'high:1', 'a:1']

    response = client.get('/api/reviews/search?collection=a_review&page_size=1')
    assert response.status_code == 200
    assert response.get_json()['total'] == 2

    response = client.get('/api/reviews/search?collection=a_review&collection=b_review&title=test')
    assert response.status_code == 200
    assert response.get_json()['total'] == 4

    response = client.get('/api/reviews/search?collection=a_review&collection=missing_review&title=test')
    assert response.status_code == 400
    assert 'not found' in response.get_json()['error']

    response = client.get('/api/reviews/search?collection=a_review&collection=b_review')
    assert response.status_code == 200
    assert response.get_json()['total'] == 4


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
    patch_iter_collection_documents(monkeypatch, views, on_query=on_query)
    monkeypatch.setattr('routes.review._attach_related_cve_documents', lambda *args: None)

    response = client.get('/api/reviews/search?mode=cve')
    assert response.status_code == 200
    assert captured == ['cve']


def test_review_search_mode_non_cve_excludes_cve_review(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
        'avd_review': {'options': {'viewOn': 'avd', 'pipeline': [{'$project': {'title': 1}}]}},
        'hkcert_review': {'options': {'viewOn': 'hkcert', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    captured = []

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    def on_query(view, mongo_filter):
        captured.append(view['options']['viewOn'])

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_iter_collection_documents(monkeypatch, views, on_query=on_query)

    response = client.get('/api/reviews/search?mode=non_cve')
    assert response.status_code == 200
    assert set(captured) == {'avd', 'hkcert'}
    assert 'cve' not in captured


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
    patch_iter_collection_documents(monkeypatch, views, documents)
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
        if source == 'cve' and is_related_query:
            return 1, [dict(cve_document)]
        if source == 'avd' and is_related_query:
            return 1, [dict(related_avd)]
        return 0, []

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_iter_collection_documents(monkeypatch, views, documents)
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


def test_auto_select_best_picks_richest_related_records_for_all_matching_cves(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
        'avd_review': {'options': {'viewOn': 'avd', 'pipeline': [{'$project': {'title': 1}}]}},
        'hkcert_review': {'options': {'viewOn': 'hkcert', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    cve_documents = [
        {
            '_id': 'cve:CVE-2026-1000',
            'code': 'CVE-2026-1000',
            'title': 'Target first CVE',
            'severity': 'High',
            'details': {},
            'scraped_at': '2026-06-18T00:00:00+00:00',
        },
        {
            '_id': 'cve:CVE-2026-2000',
            'code': 'CVE-2026-2000',
            'title': 'Target second CVE',
            'severity': 'High',
            'details': {},
            'scraped_at': '2026-06-17T00:00:00+00:00',
        },
        {
            '_id': 'cve:CVE-2026-3000',
            'code': 'CVE-2026-3000',
            'title': 'Unmatched CVE',
            'severity': 'High',
            'details': {},
            'scraped_at': '2026-06-16T00:00:00+00:00',
        },
    ]
    related_by_source = {
        'cve': cve_documents,
        'avd': [
            {
                '_id': 'avd:CVE-2026-1000',
                'code': '2026-1000',
                'title': 'Rich AVD detail',
                'severity': 'High',
                'affected': ['Product A'],
                'details': {
                    'avd': {
                        'description': 'Detailed exploitation and root-cause notes.',
                        'affected_products': ['Product A 1.0'],
                        'recommendations': ['Upgrade to 2.0'],
                        'references': ['https://example.test/avd-1000'],
                    },
                },
                'source': {'detail_url': 'https://example.test/avd-1000'},
                'scraped_at': '2026-06-17T00:00:00+00:00',
            },
            {
                '_id': 'avd:CVE-2026-2000',
                'code': '2026-2000',
                'title': 'Thin AVD detail',
                'details': {'avd': {'summary': 'Short note.'}},
                'scraped_at': '2026-06-18T00:00:00+00:00',
            },
        ],
        'hkcert': [
            {
                '_id': 'hkcert:CVE-2026-1000',
                'code': 'CVE-2026-1000',
                'title': 'Thin HKCERT detail',
                'details': {'hkcert': {'summary': 'Brief.'}},
                'scraped_at': '2026-06-18T00:00:00+00:00',
            },
            {
                '_id': 'hkcert:CVE-2026-2000',
                'code': 'CVE-2026-2000',
                'title': 'Rich HKCERT detail',
                'severity': 'High',
                'details': {
                    'hkcert': {
                        'description': 'Complete bulletin with impact and remediation.',
                        'systems_affected': ['Product B'],
                        'solutions': ['Apply the vendor patch'],
                        'solution_links': ['https://example.test/hkcert-2000'],
                    },
                },
                'source': {'detail_url': 'https://example.test/hkcert-2000'},
                'scraped_at': '2026-06-16T00:00:00+00:00',
            },
        ],
    }

    documents = {'cve_review': cve_documents}

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    def query_slice(database, view, mongo_filter, skip, limit):
        source = view['options']['viewOn']
        filter_text = str(mongo_filter)
        selected = [
            dict(document)
            for document in related_by_source[source]
            if any(code in filter_text for code in ('1000', '2000'))
            and any((document.get('code') or '').endswith(code) for code in ('1000', '2000'))
        ]
        return len(selected), selected

    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_iter_collection_documents(monkeypatch, views, documents)
    monkeypatch.setattr('routes.review._query_review_slice', query_slice)

    response = client.get('/api/reviews/auto-select-best?mode=cve&search=target&page=1&page_size=1')

    assert response.status_code == 200
    body = response.get_json()
    assert body['processed'] == 2
    assert body['selected'] == 2
    assert body['skipped'] == 0
    assert body['selections'] == [
        {'collection': 'avd_review', 'selection_id': 'avd:CVE-2026-1000'},
        {'collection': 'hkcert_review', 'selection_id': 'hkcert:CVE-2026-2000'},
    ]
    assert 'cve_review\x00cve:CVE-2026-1000' in body['selection_keys_to_remove']
    assert 'avd_review\x00avd:CVE-2026-1000' in body['selection_keys_to_remove']
    assert 'hkcert_review\x00hkcert:CVE-2026-2000' in body['selection_keys_to_remove']
    assert all('3000' not in key for key in body['selection_keys_to_remove'])


def test_auto_select_best_rejects_over_limit_matches(client, monkeypatch):
    authenticate(client)
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    cve_documents = [
        {'_id': 'cve:CVE-2026-1000', 'code': 'CVE-2026-1000', 'title': 'Target one'},
        {'_id': 'cve:CVE-2026-1001', 'code': 'CVE-2026-1001', 'title': 'Target two'},
    ]

    class FakeDatabase:
        def __getitem__(self, name):
            return None

    monkeypatch.setattr('routes.review.MAX_EXPORT_SELECTIONS', 1)
    monkeypatch.setattr('routes.review.get_vulnerabilities_database', FakeDatabase)
    monkeypatch.setattr('routes.review._review_views', lambda database: views)
    patch_iter_collection_documents(monkeypatch, views, {'cve_review': cve_documents})

    response = client.get('/api/reviews/auto-select-best?mode=cve&search=target')

    assert response.status_code == 400
    assert 'limited to 1 matching CVEs' in response.get_json()['error']


def test_review_search_keyword_matches_nested_projected_details(client, monkeypatch):
    authenticate(client)
    views = {
        'avd_review': {'options': {'viewOn': 'avd', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    captured = []

    documents = {
        'avd_review': [
            {
                '_id': 'avd:1',
                'title': 'Summary misses keyword',
                'severity': 'High',
                'details': {'source': {'description': 'contains nested-only-token'}},
            },
            {
                '_id': 'avd:2',
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
    patch_iter_collection_documents(monkeypatch, views, documents, on_query=on_query)

    response = client.get('/api/reviews/search?mode=non_cve&search=nested-only-token')

    assert response.status_code == 200
    body = response.get_json()
    assert body['total'] == 1
    assert body['data'][0]['selection_id'] == 'avd:1'
    assert 'nested-only-token' not in str(captured[0])


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
                'scraped_at': '2026-06-10T00:00:00+00:00',
                'classification': {'status': 'classified', 'best_vendor': 'Cisco'},
            },
            {
                '_id': 'cve:microsoft',
                'title': 'Microsoft issue',
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
    patch_iter_collection_documents(monkeypatch, views, documents)
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
    patch_iter_collection_documents(monkeypatch, views, documents)
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
    patch_iter_collection_documents(
        monkeypatch,
        views,
        {'cve_review': [{'_id': 'cve:1', 'title': 'Example'}]},
    )

    response = client.get('/api/reviews/search')
    assert response.status_code == 200
    assert response.get_json()['total'] == 1

    monkeypatch.setattr('routes.review._review_views', lambda database: {})
    response = client.get('/api/reviews/search?collection=not_a_review')
    assert response.status_code == 400
    assert 'not found' in response.get_json()['error']

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
    patch_iter_collection_documents(monkeypatch, views, on_query=on_query)

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
    patch_iter_collection_documents(monkeypatch, views, on_query=on_query)

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


def test_global_review_search_rejects_over_limit_matches(client, monkeypatch):
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
    patch_iter_collection_documents(monkeypatch, views, documents)

    response = client.get('/api/reviews/search?mode=cve')

    assert response.status_code == 400
    assert 'limited to 2 matching documents' in response.get_json()['error']


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

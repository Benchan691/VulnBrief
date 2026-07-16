import pytest
from pymongo.errors import ServerSelectionTimeoutError
from zoneinfo import ZoneInfo

from app import app
from subscriptions.profiles import SUB_ACCOUNT_COLLECTION
from core.database import get_web_database


HONG_KONG = ZoneInfo('Asia/Hong_Kong')
TEST_EMAIL = 'subscriptions-test@example.com'


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.app_context():
        get_web_database()[SUB_ACCOUNT_COLLECTION].delete_many({'email': TEST_EMAIL})
    client = app.test_client()
    yield client
    with app.app_context():
        get_web_database()[SUB_ACCOUNT_COLLECTION].delete_many({'email': TEST_EMAIL})


def authenticate(client):
    with client.session_transaction() as session:
        session['username'] = 'test-user'


def _mock_run_database(monkeypatch, documents_by_source):
    from core.database import get_vulnerabilities_database

    database = get_vulnerabilities_database()

    class FakeCursor:
        def __init__(self, documents):
            self.documents = documents

        def sort(self, *args, **kwargs):
            return self

        def __iter__(self):
            return iter(self.documents)

    class FakeCollection:
        def __init__(self, documents):
            self.documents = documents

        def aggregate(self, pipeline):
            return FakeCursor(self.documents)

    class WrappingDatabase:
        def __getattr__(self, name):
            return getattr(database, name)

        def __getitem__(self, name):
            if name in documents_by_source:
                return FakeCollection(documents_by_source[name])
            return database[name]

    monkeypatch.setattr(
        'subscriptions.routes.get_vulnerabilities_database',
        lambda: WrappingDatabase(),
    )


def test_subscriptions_requires_authentication(client):
    assert client.get('/subscriptions').status_code == 302
    assert client.get('/api/subscriptions').status_code == 401
    assert client.post('/api/subscriptions', json={}).status_code == 401


def test_subscriptions_crud_validates_review_views(client):
    authenticate(client)

    page = client.get('/subscriptions')
    assert page.status_code == 200
    assert b'/static/js/shared/collection-picker.js' in page.data
    assert b'/static/js/subscriptions/index.js' in page.data
    assert b'id="page-config"' in page.data

    invalid = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd'],
    })
    assert invalid.status_code == 400

    created = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review', 'hkcert_review'],
    })
    assert created.status_code == 201

    subscriptions = client.get('/api/subscriptions').get_json()['data']
    created_record = next(item for item in subscriptions if item['email'] == TEST_EMAIL)
    assert created_record['email'] == TEST_EMAIL
    assert created_record['team'] == 'Test'
    assert created_record['newsletter_profile']['enabled'] is False
    assert created_record['report_profile']['filters']['collections'] == [
        'avd_review', 'hkcert_review',
    ]

    updated = client.put(f'/api/subscriptions/{TEST_EMAIL}', json={
        'subscriptions': ['cve_review'],
    })
    assert updated.status_code == 200

    assert client.delete(f'/api/subscriptions/{TEST_EMAIL}').status_code == 200


def test_subscription_report_preview_returns_count_and_top_cves(client, monkeypatch):
    authenticate(client)

    monkeypatch.setattr(
        'subscriptions.routes.query_profile_matches',
        lambda database, profile, limit=None, include_documents=False, allow_partial=False: [
            {
                'collection': 'cve_review',
                'source_collection': 'cve',
                'selection_id': '1',
                'document': {
                    'code': 'CVE-2026-0001',
                    'severity': 'Critical',
                    'details': {'cve': {'description': 'Active exploitation with remote code execution'}},
                },
            },
            {
                'collection': 'cve_review',
                'source_collection': 'cve',
                'selection_id': '2',
                'document': {
                    'code': 'CVE-2026-0002',
                    'severity': 'High',
                    'details': {'cve': {'description': 'Proof of concept exploit'}},
                },
            },
            {
                'collection': 'cve_review',
                'source_collection': 'cve',
                'selection_id': '3',
                'document': {
                    'code': 'CVE-2026-0003',
                    'severity': 'Medium',
                    'details': {'cve': {'description': 'Moderate impact'}},
                },
            },
        ],
    )
    monkeypatch.setattr('subscriptions.routes.count_profile_matches', lambda database, profile: 3)

    response = client.post('/api/subscriptions/report-preview', json={
        'report_profile': {
            'enabled': True,
            'generation_mode': 'enriched_weekly',
            'report_language': 'en',
            'filters': {},
        },
    })

    assert response.status_code == 200
    body = response.get_json()
    assert body['count'] == 3
    assert body['top_cves'][0] == 'CVE-2026-0001'
    assert len(body['top_cves']) == 3


def test_subscription_report_preview_rejects_invalid_profile(client):
    authenticate(client)

    response = client.post('/api/subscriptions/report-preview', json={
        'report_profile': {
            'enabled': True,
            'filters': {'status': 'Urgent'},
        },
    })

    assert response.status_code == 400
    assert response.get_json()['error'].startswith('Severity/status must be')


def test_subscription_report_preview_returns_json_for_unexpected_error(client, monkeypatch):
    authenticate(client)
    monkeypatch.setattr('subscriptions.routes.count_profile_matches', lambda database, profile: 1)

    def fail_preview(*args, **kwargs):
        raise RuntimeError('Preview exploded')

    monkeypatch.setattr('subscriptions.routes.query_profile_matches', fail_preview)

    response = client.post('/api/subscriptions/report-preview', json={
        'report_profile': {
            'enabled': True,
            'generation_mode': 'enriched_weekly',
            'report_language': 'en',
            'filters': {},
        },
    })

    assert response.status_code == 500
    assert response.get_json()['error'] == 'Preview exploded'


def test_subscriptions_run_daily_window_selects_matching_source_documents(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review', 'hkcert_review'],
    }).status_code == 201

    _mock_run_database(monkeypatch, {
        'avd': [{'_id': 'avd-1'}],
        'hkcert': [{'_id': 'hk-1'}],
    })
    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/run', json={'window': 'daily'})

    assert response.status_code == 200
    body = response.get_json()
    assert body['count'] > 0
    assert all(item['collection'] in {'avd_review', 'hkcert_review'} for item in body['selections'])


def test_subscriptions_run_week_window(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review'],
    }).status_code == 201

    _mock_run_database(monkeypatch, {'avd': [{'_id': 'avd-week'}]})
    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/run', json={'window': 'week'})
    assert response.status_code == 200
    assert response.get_json()['count'] > 0


def test_subscriptions_run_custom_window(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review'],
    }).status_code == 201

    _mock_run_database(monkeypatch, {'avd': [{'_id': 'avd-custom'}]})
    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/run', json={
        'window': 'custom',
        'start': '2026-06-05T00:00',
        'end': '2026-06-06T12:00',
    })
    assert response.status_code == 200
    assert response.get_json()['count'] > 0


def test_subscriptions_run_rejects_invalid_window_and_handles_database_failure(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': [],
    }).status_code == 201

    invalid = client.post(f'/api/subscriptions/{TEST_EMAIL}/run', json={
        'window': 'custom',
        'start': '2026-06-06T12:00',
        'end': '2026-06-06T08:00',
    })
    assert invalid.status_code == 400

    def unavailable_database():
        raise ServerSelectionTimeoutError('unavailable')

    monkeypatch.setattr('subscriptions.routes.get_vulnerabilities_database', unavailable_database)
    failed = client.post(f'/api/subscriptions/{TEST_EMAIL}/run', json={'window': 'daily'})
    assert failed.status_code == 503


def test_disabled_report_profile_cannot_run(client):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {'enabled': False, 'filters': {}},
    }).status_code == 201

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/run', json={})
    assert response.status_code == 400
    assert response.get_json()['error'] == 'Report profile is disabled.'


def test_send_subscription_statistic_emails_delivery_counts(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {'enabled': True, 'filters': {'collections': ['avd_review']}},
        'report_profile': {'enabled': True},
    }).status_code == 201

    with app.app_context():
        get_web_database()['newsletter_deliveries'].delete_many({'email': TEST_EMAIL})
        get_web_database()['newsletter_deliveries'].insert_many([
            {
                'email': TEST_EMAIL,
                'database': 'vulnerabilities',
                'source_collection': 'avd',
                'selection_id': 'avd:1',
                'title': 'One',
                'sent_at': '2026-07-01T00:00:00+00:00',
            },
            {
                'email': TEST_EMAIL,
                'database': 'vulnerabilities',
                'source_collection': 'avd',
                'selection_id': 'avd:2',
                'title': 'Two',
                'sent_at': '2026-07-02T00:00:00+00:00',
            },
            {
                'email': TEST_EMAIL,
                'database': 'vulnerabilities',
                'source_collection': 'hkcert',
                'selection_id': 'hkcert:1',
                'title': 'Three',
                'sent_at': '2026-07-03T00:00:00+00:00',
            },
        ])

    sent = {}

    class FakeMailer:
        def __init__(self, config):
            self.config = config

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def send_email(self, receiver, email):
            sent.update({
                'to': receiver,
                'subject': email['subject'],
                'html': email['html'],
            })

    monkeypatch.setattr('subscriptions.routes.Mailer', FakeMailer)

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/send-statistic')
    assert response.status_code == 200
    body = response.get_json()
    assert body['message'] == 'Newsletter statistics email sent.'
    assert body['statistics']['total'] == 3
    assert body['statistics']['databases'] == ['vulnerabilities']
    assert sent['to'] == TEST_EMAIL
    assert sent['subject'] == 'Newsletter delivery statistics'
    assert 'Total newsletters sent' in sent['html']
    assert 'avd' in sent['html']
    assert 'hkcert' in sent['html']

    with app.app_context():
        get_web_database()['newsletter_deliveries'].delete_many({'email': TEST_EMAIL})


def test_send_subscription_statistic_requires_newsletter_enabled(client):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {'enabled': False},
        'report_profile': {'enabled': True},
    }).status_code == 201

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/send-statistic')
    assert response.status_code == 400
    assert response.get_json()['error'] == 'Newsletter feed is disabled for this subscription.'


def test_subscription_rejects_invalid_severity_choice(client):
    authenticate(client)
    response = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {
            'enabled': True,
            'filters': {'status': 'Urgent'},
        },
    })
    assert response.status_code == 400
    assert response.get_json()['error'].startswith('Severity/status must be')


def test_report_profile_accepts_schedule_and_keywords(client):
    authenticate(client)
    response = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {
            'enabled': True,
            'generation_mode': 'enriched_weekly',
            'report_language': 'zh',
            'schedule_enabled': True,
            'schedule_weekday': 'fri',
            'schedule_time': '14:30',
            'filters': {
                'keywords': [' Red Hat ', 'redhat', 'Enterprise Linux'],
            },
        },
    })

    assert response.status_code == 201
    item = next(item for item in client.get('/api/subscriptions').get_json()['data'] if item['email'] == TEST_EMAIL)
    assert item['report_profile']['schedule_enabled'] is True
    assert item['report_profile']['schedule_weekday'] == 'fri'
    assert item['report_profile']['schedule_time'] == '14:30'
    assert item['report_profile']['next_run_at']
    assert item['report_profile']['filters']['keywords'] == ['Red Hat', 'Enterprise Linux']


def test_report_profile_rejects_invalid_schedule_and_keywords(client):
    authenticate(client)
    bad_schedule = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {'schedule_enabled': True, 'schedule_weekday': 'funday'},
    })
    assert bad_schedule.status_code == 400

    bad_keywords = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {'filters': {'keywords': 'redhat'}},
    })
    assert bad_keywords.status_code == 400


def _newsletter_match(document):
    return {
        'collection': 'avd_review',
        'source_collection': 'avd',
        'selection_id': document['_id'],
        'document': document,
    }


def test_newsletter_feed_query_returns_intersecting_newsletters(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {'enabled': True, 'filters': {'collections': ['avd_review']}},
    }).status_code == 201

    page = client.get(f'/subscriptions/{TEST_EMAIL}/newsletter-feed')
    assert page.status_code == 200
    assert b'/static/js/newsletters/feed.js' in page.data
    assert b'id="page-config"' in page.data
    assert b'Search all' not in page.data

    document = {
        '_id': 'avd-1',
        'title': 'Matched Advisory',
        'scraped_at': '2026-06-15T12:00:00+00:00',
        'details': {'avd': {'summary': 'Matched summary'}},
    }
    monkeypatch.setattr(
        'newsletters.feed.query_profile_matches',
        lambda database, profile, limit=None, include_documents=False: [
            _newsletter_match(document) if include_documents else {
                'collection': 'avd_review',
                'source_collection': 'avd',
                'selection_id': 'avd-1',
            },
        ],
    )

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/newsletters/query', json={
        'filters': {'collections': ['avd_review']},
    })
    assert response.status_code == 200
    body = response.get_json()
    assert body['count'] == 1
    assert len(body['data']) == 1
    assert body['data'][0]['title'] == 'Matched Advisory'
    assert body['data'][0]['source_collection'] == 'avd'
    assert body['data'][0]['selection_id'] == 'avd-1'
    assert 'html' not in body['data'][0]


def test_newsletter_feed_query_requires_authentication(client):
    assert client.post(
        f'/api/subscriptions/{TEST_EMAIL}/newsletters/query',
        json={'filters': {}},
    ).status_code == 401


def test_newsletter_feed_query_returns_empty_when_no_matches(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {'enabled': True, 'filters': {}},
    }).status_code == 201

    monkeypatch.setattr('newsletters.feed.query_profile_matches', lambda *args, **kwargs: [])

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/newsletters/query', json={
        'filters': {'collections': ['avd_review']},
    })
    assert response.status_code == 200
    body = response.get_json()
    assert body['count'] == 0
    assert body['data'] == []


def test_newsletter_feed_query_unknown_subscription_returns_404(client):
    authenticate(client)
    response = client.post(
        '/api/subscriptions/missing@example.com/newsletters/query',
        json={'filters': {}},
    )
    assert response.status_code == 404


def test_newsletter_feed_query_rejects_disabled_profile(client):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {'enabled': False, 'filters': {}},
    }).status_code == 201

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/newsletters/query', json={
        'filters': {},
    })
    assert response.status_code == 400
    assert response.get_json()['error'] == 'Newsletter feed is disabled for this subscription.'


def test_newsletter_feed_query_uses_collections_only(client):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {'enabled': True, 'filters': {}},
    }).status_code == 201

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/newsletters/query', json={
        'filters': {'status': 'Urgent'},
    })
    assert response.status_code == 200

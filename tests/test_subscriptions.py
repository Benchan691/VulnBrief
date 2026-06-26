import pytest
from pymongo.errors import ServerSelectionTimeoutError
from zoneinfo import ZoneInfo

from app import app
from subscription_data import SUB_ACCOUNT_COLLECTION
from mongo import get_web_database


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
    from mongo import get_vulnerabilities_database

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
        'routes.subscription.get_vulnerabilities_database',
        lambda: WrappingDatabase(),
    )


def test_subscriptions_requires_authentication(client):
    assert client.get('/subscriptions').status_code == 302
    assert client.get('/api/subscriptions').status_code == 401
    assert client.post('/api/subscriptions', json={}).status_code == 401


def test_subscriptions_crud_validates_review_views(client):
    authenticate(client)

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


def test_verify_subscription_email_sends_test_message(client, monkeypatch):
    authenticate(client)
    sent = {}
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {'enabled': True},
    }).status_code == 201
    monkeypatch.setattr(
        'routes.subscription.send_html_email',
        lambda config, to, subject, html: sent.update({
            'to': to,
            'subject': subject,
            'html': html,
        }),
    )

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/verify-email')

    assert response.status_code == 200
    assert response.get_json()['message'] == 'Verification email sent.'
    assert sent['to'] == TEST_EMAIL
    assert sent['subject'] == 'Security Portal email verification'
    assert 'test email' in sent['html']


def test_verify_subscription_email_returns_send_error(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {'enabled': True},
    }).status_code == 201

    def fail_send(*args):
        raise RuntimeError('SMTP refused connection')

    monkeypatch.setattr('routes.subscription.send_html_email', fail_send)

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/verify-email')

    assert response.status_code == 502
    assert response.get_json()['error'] == 'SMTP refused connection'


def test_subscription_report_preview_returns_count_and_top_cves(client, monkeypatch):
    authenticate(client)

    monkeypatch.setattr(
        'routes.subscription.query_profile_matches',
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
    monkeypatch.setattr('routes.subscription.count_profile_matches', lambda database, profile: 3)

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
    monkeypatch.setattr('routes.subscription.count_profile_matches', lambda database, profile: 1)

    def fail_preview(*args, **kwargs):
        raise RuntimeError('Preview exploded')

    monkeypatch.setattr('routes.subscription.query_profile_matches', fail_preview)

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

    monkeypatch.setattr('routes.subscription.get_vulnerabilities_database', unavailable_database)
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


def test_send_subscription_report_generates_job_and_emails(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {'enabled': True, 'filters': {}},
    }).status_code == 201

    class FakeThread:
        def __init__(self, target=None, args=None, daemon=None):
            self.target = target
            self.args = args or ()

        def start(self):
            return None

    monkeypatch.setattr('routes.subscription.threading.Thread', FakeThread)
    monkeypatch.setattr(
        'routes.subscription.start_subscription_report_job',
        lambda subscription, profile: {
            'job_id': 'job-123',
        },
    )

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/send-email')

    assert response.status_code == 202
    body = response.get_json()
    assert body['job_id'] == 'job-123'


def test_send_subscription_report_background_has_app_context(monkeypatch):
    import routes.subscription as subscription_routes
    from flask import current_app

    updates = []

    class FakeCollection:
        def update_one(self, *args, **kwargs):
            updates.append((args, kwargs))

    def fake_deliver(app_obj, subscription, profile, job_id, **kwargs):
        assert current_app._get_current_object() is app

    monkeypatch.setattr(subscription_routes, 'get_collection', lambda: FakeCollection())
    monkeypatch.setattr(subscription_routes, 'deliver_subscription_report_job', fake_deliver)

    subscription_routes._send_subscription_report_background(
        app,
        'raw-id',
        {'email': TEST_EMAIL},
        {'generation_mode': 'template'},
        'job-123',
        1,
    )

    assert updates


def test_send_subscription_report_returns_no_match_error(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {'enabled': True, 'filters': {}},
    }).status_code == 201

    def fail_generate(*args, **kwargs):
        raise ValueError('No records matched the report profile.')

    monkeypatch.setattr('routes.subscription.start_subscription_report_job', fail_generate)

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/send-email')

    assert response.status_code == 400
    assert response.get_json()['error'] == 'No records matched the report profile.'


def test_send_subscription_report_surfaces_smtp_failure(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {'enabled': True, 'filters': {}},
    }).status_code == 201

    def fail_generate(*args, **kwargs):
        raise RuntimeError('SMTP refused connection')

    monkeypatch.setattr('routes.subscription.start_subscription_report_job', fail_generate)

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/send-email')

    assert response.status_code == 502
    assert response.get_json()['error'] == 'SMTP refused connection'


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

    document = {
        '_id': 'avd-1',
        'title': 'Matched Advisory',
        'scraped_at': '2026-06-15T12:00:00+00:00',
        'details': {'avd': {'summary': 'Matched summary'}},
    }
    monkeypatch.setattr(
        'newsletter_store.query_profile_matches',
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

    monkeypatch.setattr('newsletter_store.query_profile_matches', lambda *args, **kwargs: [])

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


def test_newsletter_feed_query_rejects_invalid_filters(client):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {'enabled': True, 'filters': {}},
    }).status_code == 201

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/newsletters/query', json={
        'filters': {'status': 'Urgent'},
    })
    assert response.status_code == 400
    assert response.get_json()['error'].startswith('Severity/status must be')

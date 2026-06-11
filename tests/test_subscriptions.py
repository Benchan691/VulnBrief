from datetime import datetime

import pytest
from pymongo.errors import ServerSelectionTimeoutError
from zoneinfo import ZoneInfo

from app import app
from mongo import get_web_database


HONG_KONG = ZoneInfo('Asia/Hong_Kong')
TEST_EMAIL = 'subscriptions-test@example.com'


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.app_context():
        get_web_database()['subscriptions'].delete_many({'email': TEST_EMAIL})
    client = app.test_client()
    yield client
    with app.app_context():
        get_web_database()['subscriptions'].delete_many({'email': TEST_EMAIL})


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

        def find(self, mongo_filter, projection):
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
    assert created_record == {
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review', 'hkcert_review'],
    }

    updated = client.put(f'/api/subscriptions/{TEST_EMAIL}', json={
        'subscriptions': ['cve_review'],
    })
    assert updated.status_code == 200

    assert client.delete(f'/api/subscriptions/{TEST_EMAIL}').status_code == 200


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
    monkeypatch.setattr('routes.subscription._boundary_times', lambda: {
        'yesterday_00': datetime(2026, 6, 5, 0, 0, tzinfo=HONG_KONG),
        'today_00': datetime(2026, 6, 6, 0, 0, tzinfo=HONG_KONG),
        'week_ago_00': datetime(2026, 5, 30, 0, 0, tzinfo=HONG_KONG),
        'now': datetime(2026, 6, 6, 12, 0, tzinfo=HONG_KONG),
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
    monkeypatch.setattr('routes.subscription._boundary_times', lambda: {
        'yesterday_00': datetime(2026, 6, 5, 0, 0, tzinfo=HONG_KONG),
        'today_00': datetime(2026, 6, 6, 0, 0, tzinfo=HONG_KONG),
        'week_ago_00': datetime(2026, 5, 30, 0, 0, tzinfo=HONG_KONG),
        'now': datetime(2026, 6, 6, 12, 0, tzinfo=HONG_KONG),
    })
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

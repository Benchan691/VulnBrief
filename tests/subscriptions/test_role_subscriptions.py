from datetime import datetime, timezone

import pytest

from app import app
from auth.store import ROLE_USER, find_user, upsert_user, verify_login
from core.database import get_web_database
from subscriptions.profiles import SUB_ACCOUNT_COLLECTION
from tests.auth_helpers import authenticate as authenticate_admin


USER_USERNAME = 'subscription-role-user'
USER_EMAIL = 'subscription-role-user@example.com'
OTHER_EMAIL = 'subscription-role-other@example.com'


def _subscription(email, *, report_enabled=False):
    now = datetime.now(timezone.utc)
    return {
        'email': email,
        'team': email.split('@')[0],
        'newsletter_profile': {'enabled': False, 'filters': {}},
        'report_profile': {'enabled': report_enabled, 'filters': {}},
        'created_at': now,
        'updated_at': now,
    }


def _clean_records():
    database = get_web_database()
    database[SUB_ACCOUNT_COLLECTION].delete_many({
        'email': {'$in': [USER_EMAIL, OTHER_EMAIL]},
    })
    database['auth'].delete_many({
        '$or': [
            {'username': USER_USERNAME},
            {'email': {'$in': [USER_EMAIL, OTHER_EMAIL]}},
        ],
    })


@pytest.fixture(autouse=True)
def fake_mailer(monkeypatch):
    class FakeMailer:
        def __init__(self, config):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def send_email(self, receiver, email):
            pass

    monkeypatch.setattr('subscriptions.routes.Mailer', FakeMailer)


def _authenticate_user(client):
    with app.app_context():
        upsert_user(
            USER_USERNAME,
            'user-password',
            email=USER_EMAIL,
            role=ROLE_USER,
        )
    with client.session_transaction() as session:
        session['username'] = USER_USERNAME


def test_user_can_manage_only_own_subscription_and_cannot_open_admin_tools(monkeypatch):
    app.config.update(TESTING=True)
    _clean_records()
    client = app.test_client()
    try:
        _authenticate_user(client)
        with app.app_context():
            collection = get_web_database()[SUB_ACCOUNT_COLLECTION]
            collection.insert_one(_subscription(USER_EMAIL))
            collection.insert_one(_subscription(OTHER_EMAIL))

        subscriptions = client.get('/api/subscriptions')
        assert subscriptions.status_code == 200
        assert [item['email'] for item in subscriptions.get_json()['data']] == [USER_EMAIL]

        assert client.get('/reviews').status_code == 403
        assert client.get('/operations').status_code == 403
        assert client.get('/reports').status_code == 403
        assert client.get('/api/reviews').status_code == 403
        assert client.get('/api/reports').status_code == 403
        assert client.get('/reports/not-a-job/download').status_code == 403
        assert client.get('/generated-newsletters/cve/cve-1/preview').status_code == 403
        assert client.post('/set-news', json={}).status_code == 403
        assert client.get('/api/operations/source-list').status_code == 403
        assert client.post('/api/subscriptions', json={}).status_code == 403
        assert client.post('/api/subscriptions/preview', json={'mode': 'create'}).status_code == 403
        user_page = client.get('/subscriptions')
        assert user_page.status_code == 200
        assert b'id="add-btn"' not in user_page.data
        assert b'id="password"' not in user_page.data

        other_path = f'/api/subscriptions/{OTHER_EMAIL}'
        assert client.put(other_path, json={'team': 'Nope'}).status_code == 403
        assert client.delete(other_path).status_code == 403
        assert client.post(other_path + '/run').status_code == 403
        assert client.post(other_path + '/send-statistic').status_code == 403

        assert client.get('/settings').status_code == 200
        assert client.put(f'/api/subscriptions/{USER_EMAIL}', json={'team': 'Updated'}).status_code == 200
        assert client.delete(f'/api/subscriptions/{USER_EMAIL}').status_code == 200
        with app.app_context():
            assert find_user(USER_EMAIL) is not None
            assert verify_login(USER_EMAIL, 'user-password') is not None
    finally:
        with app.app_context():
            _clean_records()


def test_admin_creates_and_resets_user_password_without_exposing_it(monkeypatch):
    app.config.update(TESTING=True)
    _clean_records()
    client = app.test_client()
    try:
        authenticate_admin(client)
        admin_page = client.get('/subscriptions')
        assert admin_page.status_code == 200
        assert b'id="add-btn"' in admin_page.data
        assert b'id="password"' in admin_page.data
        missing_password = client.post('/api/subscriptions', json={
            'email': USER_EMAIL,
            'team': 'User',
        })
        assert missing_password.status_code == 400

        created = client.post('/api/subscriptions', json={
            'email': USER_EMAIL,
            'team': 'User',
            'password': 'initial-password',
            'newsletter_profile': {'enabled': False, 'filters': {}},
            'report_profile': {'enabled': False, 'filters': {}},
        })
        assert created.status_code == 201
        body = client.get('/api/subscriptions').get_json()
        assert 'password' not in str(body)
        with app.app_context():
            user = find_user(USER_EMAIL)
            assert user['role'] == ROLE_USER
            assert 'password' in user
            assert verify_login(USER_EMAIL, 'initial-password') is not None

        reset = client.put(f'/api/subscriptions/{USER_EMAIL}', json={
            'password': 'reset-password',
        })
        assert reset.status_code == 200
        with app.app_context():
            assert verify_login(USER_EMAIL, 'initial-password') is None
            assert verify_login(USER_EMAIL, 'reset-password') is not None

        assert client.delete(f'/api/subscriptions/{USER_EMAIL}').status_code == 200
        with app.app_context():
            assert find_user(USER_EMAIL) is not None
            assert verify_login(USER_EMAIL, 'reset-password') is not None
    finally:
        with app.app_context():
            _clean_records()

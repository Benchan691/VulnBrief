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
GROUP_USERNAME = 'grouped-subscription-user'
GROUP_EMAILS = [
    'group-a@example.com',
    'group-b@example.com',
    'group-c@example.com',
]


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
        '$or': [
            {'email': {'$in': [USER_EMAIL, OTHER_EMAIL, *GROUP_EMAILS]}},
            {'emails': {'$in': [USER_EMAIL, OTHER_EMAIL, *GROUP_EMAILS]}},
            {'username': {'$in': [USER_USERNAME, GROUP_USERNAME, 'renamed-grouped-user']}},
        ],
    })
    database['auth'].delete_many({
        '$or': [
            {'username': {'$in': [USER_USERNAME, GROUP_USERNAME, 'renamed-grouped-user']}},
            {'email': {'$in': [USER_EMAIL, OTHER_EMAIL, *GROUP_EMAILS]}},
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
        assert b'id="add-recipient-btn"' not in user_page.data

        other_path = f'/api/subscriptions/{OTHER_EMAIL}'
        assert client.put(other_path, json={'team': 'Nope'}).status_code == 403
        assert client.delete(other_path).status_code == 403
        assert client.post(other_path + '/run').status_code == 403
        assert client.post(other_path + '/send-statistic').status_code == 403

        assert client.get('/settings').status_code == 200
        assert client.put(f'/api/subscriptions/{USER_EMAIL}', json={'team': 'Updated'}).status_code == 200
        assert client.delete(f'/api/subscriptions/{USER_EMAIL}').status_code == 200
        with app.app_context():
            assert find_user(USER_USERNAME) is not None
            assert verify_login(USER_USERNAME, 'user-password') is not None
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
        assert b'id="recipient-list"' in admin_page.data
        assert b'id="add-recipient-btn"' in admin_page.data
        assert b'id="delivery-mode"' in admin_page.data
        assert b'Email delivery mode' in admin_page.data
        missing_password = client.post('/api/subscriptions', json={
            'email': USER_EMAIL,
            'team': 'User',
        })
        assert missing_password.status_code == 400

        created = client.post('/api/subscriptions', json={
            'username': USER_USERNAME,
            'emails': [USER_EMAIL],
            'team': 'User',
            'password': 'initial-password',
            'newsletter_profile': {'enabled': False, 'filters': {}},
            'report_profile': {'enabled': False, 'filters': {}},
        })
        assert created.status_code == 201
        body = client.get('/api/subscriptions').get_json()
        assert 'password' not in str(body)
        created_record = next(item for item in body['data'] if item['username'] == USER_USERNAME)
        with app.app_context():
            user = find_user(USER_USERNAME)
            assert user['role'] == ROLE_USER
            assert 'password' in user
            assert verify_login(USER_USERNAME, 'initial-password') is not None
            assert verify_login(USER_EMAIL, 'initial-password') is None

        reset = client.put(f"/api/subscriptions/{created_record['id']}", json={
            'password': 'reset-password',
        })
        assert reset.status_code == 200
        with app.app_context():
            assert verify_login(USER_USERNAME, 'initial-password') is None
            assert verify_login(USER_USERNAME, 'reset-password') is not None

        assert client.delete(f"/api/subscriptions/{created_record['id']}").status_code == 200
        with app.app_context():
            assert find_user(USER_USERNAME) is not None
            assert verify_login(USER_USERNAME, 'reset-password') is not None
    finally:
        with app.app_context():
            _clean_records()


def test_grouped_subscription_uses_username_and_allows_only_shared_settings_for_user():
    app.config.update(TESTING=True)
    _clean_records()
    admin_client = app.test_client()
    user_client = app.test_client()
    try:
        authenticate_admin(admin_client)
        created = admin_client.post('/api/subscriptions', json={
            'username': GROUP_USERNAME,
            'emails': [GROUP_EMAILS[0].upper(), GROUP_EMAILS[0], GROUP_EMAILS[1]],
            'team': 'Grouped SOC',
            'delivery_mode': 'grouped',
            'password': 'shared-password',
            'newsletter_profile': {'enabled': False, 'filters': {}},
            'report_profile': {'enabled': False, 'filters': {}},
        })
        assert created.status_code == 201
        subscription_id = created.get_json()['id']

        public = admin_client.get('/api/subscriptions').get_json()['data']
        record = next(item for item in public if item['id'] == subscription_id)
        assert record['username'] == GROUP_USERNAME
        assert record['emails'] == GROUP_EMAILS[:2]
        assert record['delivery_mode'] == 'grouped'
        assert 'owner_user_id' not in record
        assert 'password' not in str(record)
        assert 'password_hash' not in str(record)

        duplicate_username = admin_client.post('/api/subscriptions', json={
            'username': GROUP_USERNAME.upper(),
            'emails': [GROUP_EMAILS[2]],
            'team': 'Other',
            'password': 'other-password',
        })
        assert duplicate_username.status_code == 409

        duplicate_recipient = admin_client.post('/api/subscriptions', json={
            'username': 'another-grouped-user',
            'emails': [GROUP_EMAILS[1]],
            'team': 'Other',
            'password': 'other-password',
        })
        assert duplicate_recipient.status_code == 409

        invalid_recipient = admin_client.post('/api/subscriptions', json={
            'username': 'invalid-grouped-user',
            'emails': ['not-an-email'],
            'team': 'Other',
            'password': 'other-password',
        })
        assert invalid_recipient.status_code == 400

        login = user_client.post('/login', data={
            'username': GROUP_USERNAME,
            'password': 'shared-password',
        }, follow_redirects=False)
        assert login.status_code == 302
        assert user_client.post('/login', data={
            'username': GROUP_EMAILS[0],
            'password': 'shared-password',
        }).status_code == 200

        identity_edit = user_client.put(
            f'/api/subscriptions/{subscription_id}',
            json={'username': 'not-allowed', 'emails': [GROUP_EMAILS[2]]},
        )
        assert identity_edit.status_code == 403

        settings_edit = user_client.put(
            f'/api/subscriptions/{subscription_id}',
            json={'team': 'Updated SOC', 'delivery_mode': 'individual'},
        )
        assert settings_edit.status_code == 200

        renamed = admin_client.put(f'/api/subscriptions/{subscription_id}', json={
            'username': 'renamed-grouped-user',
            'emails': [GROUP_EMAILS[1], GROUP_EMAILS[2]],
            'delivery_mode': 'grouped',
            'password': 'renamed-password',
        })
        assert renamed.status_code == 200
        with app.app_context():
            assert verify_login(GROUP_USERNAME, 'shared-password') is None
            assert verify_login('renamed-grouped-user', 'renamed-password') is not None
            assert verify_login(GROUP_EMAILS[1], 'renamed-password') is None

        updated = user_client.get('/api/subscriptions').get_json()['data']
        assert updated[0]['username'] == 'renamed-grouped-user'
        assert updated[0]['emails'] == [GROUP_EMAILS[1], GROUP_EMAILS[2]]
        assert updated[0]['team'] == 'Updated SOC'
        assert updated[0]['delivery_mode'] == 'grouped'
    finally:
        with app.app_context():
            _clean_records()

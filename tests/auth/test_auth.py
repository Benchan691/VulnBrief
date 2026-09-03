import bcrypt

import pytest

from app import app
from auth.store import (
    ROLE_ADMIN,
    ROLE_USER,
    ensure_bootstrap_user,
    ensure_legacy_subscription_users,
    upsert_user,
    verify_login,
)
from core.database import get_web_database


@pytest.fixture(autouse=True)
def clear_auth():
    with app.app_context():
        get_web_database()['auth'].delete_many({})
    yield
    with app.app_context():
        get_web_database()['auth'].delete_many({})


def test_bootstrap_creates_default_user_when_auth_is_empty():
    with app.app_context():
        assert ensure_bootstrap_user(app.config) is True
        user = get_web_database()['auth'].find_one({'username': 'admin'})
        assert user is not None
        assert user['password'].startswith('$2')
        assert user['role'] == ROLE_ADMIN
        assert user['must_change_password'] is False
        assert verify_login('admin', app.config['WEB_AUTH_BOOTSTRAP_PASSWORD']) is not None


def test_login_rejects_email_even_when_stored_on_user():
    with app.app_context():
        upsert_user('admin', 'secret-pass', email='ops@example.com')

    client = app.test_client()
    rejected = client.post('/login', data={
        'username': 'ops@example.com',
        'password': 'secret-pass',
    }, follow_redirects=False)
    assert rejected.status_code == 200
    assert b'Invalid username or password' in rejected.data

    response = client.post('/login', data={
        'username': 'admin',
        'password': 'secret-pass',
    }, follow_redirects=False)
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session['username'] == 'admin'


def test_login_rejects_wrong_password():
    with app.app_context():
        upsert_user('admin', 'secret-pass')

    client = app.test_client()
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'wrong',
    })

    assert response.status_code == 200
    assert b'Invalid username or password' in response.data


def test_login_rejects_plain_text_password_hash():
    with app.app_context():
        get_web_database()['auth'].insert_one({
            'username': 'legacy',
            'password': 'plain-text',
        })

    client = app.test_client()
    response = client.post('/login', data={
        'username': 'legacy',
        'password': 'plain-text',
    })

    assert response.status_code == 200
    assert b'Invalid username or password' in response.data


def test_user_is_forced_to_change_password_and_can_logout():
    with app.app_context():
        upsert_user(
            'forced-user',
            '1234',
            email='forced@example.com',
            role=ROLE_USER,
            must_change_password=True,
        )

    client = app.test_client()
    response = client.post('/login', data={
        'username': 'forced-user',
        'password': '1234',
    }, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers['Location'].endswith('/settings')
    assert client.get('/subscriptions').status_code == 302
    blocked_api = client.get('/api/subscriptions')
    assert blocked_api.status_code == 403
    assert blocked_api.get_json()['code'] == 'password_change_required'

    wrong = client.post('/api/auth/password', json={
        'current_password': 'wrong',
        'new_password': 'new-user-password',
        'new_password_confirmation': 'new-user-password',
    })
    assert wrong.status_code == 400

    changed = client.post('/api/auth/password', json={
        'current_password': '1234',
        'new_password': 'new-user-password',
        'new_password_confirmation': 'new-user-password',
    })
    assert changed.status_code == 200
    assert client.get('/subscriptions').status_code == 200

    logged_out = client.get('/logout')
    assert logged_out.status_code == 302
    assert logged_out.headers['Location'].endswith('/login')
    assert client.get('/settings').status_code == 302
    with app.app_context():
        assert verify_login('forced-user', 'new-user-password') is not None
        assert verify_login('forced@example.com', 'new-user-password') is None


def test_subscription_user_edit_without_password_preserves_forced_change():
    from auth.store import ensure_subscription_user, find_user_by_id

    with app.app_context():
        upsert_user(
            'legacy-user',
            '1234',
            email='legacy-user@example.com',
            role=ROLE_USER,
            must_change_password=True,
        )
        user = find_user_by_id(get_web_database()['auth'].find_one({
            'username': 'legacy-user',
        })['_id'])
        ensure_subscription_user(
            'legacy-user',
            email='legacy-user@example.com',
            user_id=user['_id'],
        )
        updated = find_user_by_id(user['_id'])

    assert updated['must_change_password'] is True
    assert verify_login('legacy-user', '1234') is not None


def test_legacy_accounts_and_subscriptions_are_migrated():
    subscription_email = 'legacy-subscription@example.com'
    with app.app_context():
        auth = get_web_database()['auth']
        auth.insert_one({'username': 'legacy', 'password': 'plain-text'})
        get_web_database()['sub_account'].delete_many({'email': subscription_email})
        get_web_database()['sub_account'].insert_one({'email': subscription_email})

        ensure_bootstrap_user(app.config)
        ensure_legacy_subscription_users()

        admins = list(auth.find({'role': ROLE_ADMIN}))
        legacy = auth.find_one({'username': 'legacy'})
        linked = auth.find_one({'email': subscription_email})

    assert len(admins) == 1
    assert legacy['role'] == ROLE_USER
    assert legacy['must_change_password'] is True
    assert legacy['password'].startswith('$2')
    assert verify_login('legacy', '1234') is not None
    assert linked['role'] == ROLE_USER
    assert linked['must_change_password'] is True
    assert verify_login(subscription_email, '1234') is not None
    with app.app_context():
        get_web_database()['sub_account'].delete_many({'email': subscription_email})

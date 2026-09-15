from unittest.mock import Mock

import pytest

from app import app
from auth.store import AUTH_SOURCE_ACCOUNT_HUB, ensure_account_hub_user, upsert_user
from core.database import get_web_database
from integrations.account_hub import AccountHubInvalid, AccountHubClient


PREFIX = 'account-hub-test-'


@pytest.fixture(autouse=True)
def account_hub_config(monkeypatch):
    values = {
        'ACCOUNT_HUB_ENABLED': True,
        'ACCOUNT_HUB_AUTHORIZE_URL': 'https://hub.example/authorize',
        'ACCOUNT_HUB_TOKEN_URL': 'https://hub.example/token',
        'ACCOUNT_HUB_TOKEN_CHECK_URL': 'https://hub.example/check',
        'ACCOUNT_HUB_LOGOUT_URL': 'https://hub.example/logout',
        'ACCOUNT_HUB_CLIENT_ID': 'portal',
        'ACCOUNT_HUB_CLIENT_SECRET': 'secret',
        'ACCOUNT_HUB_REDIRECT_URI': 'https://portal.example/auth/account-hub/callback',
        'ACCOUNT_HUB_SCOPE': 'openid',
        'ACCOUNT_HUB_ADMIN_PERMISSION': 'portal:admin',
        'ACCOUNT_HUB_SUB_ADMIN_PERMISSION': 'portal:sub-admin',
    }
    for key, value in values.items():
        monkeypatch.setitem(app.config, key, value)
    with app.app_context():
        auth = get_web_database()['auth']
        auth.delete_many({'username': {'$regex': f'^{PREFIX}'}})
        get_web_database()['sub_account'].delete_many({'username': {'$regex': f'^{PREFIX}'}})
        admin = auth.find_one({
            'auth_source': 'local',
            'role': 'admin',
        })
        if admin is None:
            upsert_user(f'{PREFIX}admin', 'bootstrap-password', role='admin')
            admin = auth.find_one({'username': f'{PREFIX}admin'})
        monkeypatch.setitem(app.config, 'WEB_AUTH_BOOTSTRAP_USERNAME', admin['username'])
    yield
    with app.app_context():
        database = get_web_database()
        database['auth'].delete_many({'username': {'$regex': f'^{PREFIX}'}})
        database['sub_account'].delete_many({'username': {'$regex': f'^{PREFIX}'}})


def _bootstrap_session(client):
    with client.session_transaction() as session:
        session.clear()
        session['username'] = app.config['WEB_AUTH_BOOTSTRAP_USERNAME']


def _state(client):
    with client.session_transaction() as session:
        return session['account_hub_state']


def _claims(username='alice', uid=42, permissions=None):
    return {
        'uid': str(uid),
        'username': username,
        'email': f'{username}@example.com',
        'permissions': set(permissions or ()),
    }


def test_login_callback_binds_approved_user_and_revalidates_every_request(monkeypatch):
    client = app.test_client()
    with app.app_context():
        ensure_account_hub_user(f'{PREFIX}alice', 'alice@example.com')

    begin = client.get('/login?next=/settings')
    assert begin.status_code == 302
    assert begin.headers['Location'].startswith('https://hub.example/authorize?')
    state = _state(client)

    monkeypatch.setattr(AccountHubClient, 'exchange_code', lambda self, code: ('access', 'refresh'))
    monkeypatch.setattr(
        AccountHubClient,
        'check_tokens',
        lambda self, access, refresh: _claims(
            f'{PREFIX}alice', 42, {'portal:sub-admin'},
        ),
    )
    callback = client.get(f'/auth/account-hub/callback?code=code&state={state}')
    assert callback.status_code == 302
    assert callback.headers['Location'].endswith('/settings')
    with client.session_transaction() as session:
        assert session['auth_method'] == AUTH_SOURCE_ACCOUNT_HUB
        assert session['username'] == f'{PREFIX}alice'

    with app.app_context():
        user = get_web_database()['auth'].find_one({'username': f'{PREFIX}alice'})
        assert user['account_hub_uid'] == '42'
        assert user['role'] == 'sub_admin'

    revoked = Mock(side_effect=AccountHubInvalid('revoked'))
    monkeypatch.setattr(AccountHubClient, 'check_tokens', revoked)
    response = client.get('/settings')
    assert response.status_code == 302
    assert response.headers['Location'].startswith('/login?next=')
    with client.session_transaction() as session:
        assert not session


def test_unknown_account_hub_identity_is_rejected(monkeypatch):
    client = app.test_client()
    client.get('/login')
    state = _state(client)
    monkeypatch.setattr(AccountHubClient, 'exchange_code', lambda self, code: ('access', 'refresh'))
    monkeypatch.setattr(
        AccountHubClient,
        'check_tokens',
        lambda self, access, refresh: _claims(f'{PREFIX}unknown', 999),
    )
    response = client.get(f'/auth/account-hub/callback?code=code&state={state}')
    assert response.status_code == 403
    assert b'not approved' in response.data


def test_legacy_local_user_cookie_is_expired_when_sso_is_enabled():
    client = app.test_client()
    with app.app_context():
        upsert_user(f'{PREFIX}legacy', 'legacy-password', role='user')
    with client.session_transaction() as session:
        session['username'] = f'{PREFIX}legacy'
    response = client.get('/api/subscriptions')
    assert response.status_code == 401


def test_account_hub_user_admin_api_has_no_local_role_password_or_delete():
    client = app.test_client()
    _bootstrap_session(client)

    created = client.post('/api/admin/account-users', json={
        'username': f'{PREFIX}new',
        'email': 'new@example.com',
        'role': 'admin',
    })
    assert created.status_code == 400

    created = client.post('/api/admin/account-users', json={
        'username': f'{PREFIX}new',
        'email': 'new@example.com',
    })
    assert created.status_code == 201
    item = created.get_json()['data']
    assert item['auth_source'] == AUTH_SOURCE_ACCOUNT_HUB
    assert item['role'] == 'user'
    assert item['account_hub_bound'] is False
    assert 'password' not in item

    disabled = client.put(f"/api/admin/account-users/{item['id']}", json={'disabled': True})
    assert disabled.status_code == 200
    assert disabled.get_json()['data']['disabled'] is True
    assert client.delete(f"/api/admin/account-users/{item['id']}").status_code == 405


def test_account_hub_subscription_creation_has_no_local_password(monkeypatch):
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
    client = app.test_client()
    _bootstrap_session(client)
    response = client.post('/api/subscriptions', json={
        'username': f'{PREFIX}subscriber',
        'emails': [f'{PREFIX}subscriber@example.com'],
        'team': 'Account Hub',
        'newsletter_profile': {'enabled': False, 'filters': {}},
        'report_profile': {'enabled': False, 'filters': {}},
    })
    assert response.status_code == 201
    with app.app_context():
        user = get_web_database()['auth'].find_one({'username': f'{PREFIX}subscriber'})
        assert user['auth_source'] == AUTH_SOURCE_ACCOUNT_HUB
        assert 'password' not in user
    page = client.get('/subscriptions')
    assert page.status_code == 200
    assert b'id="password"' not in page.data
    subscription_id = response.get_json()['id']
    rejected = client.put(f'/api/subscriptions/{subscription_id}', json={'password': 'local-password'})
    assert rejected.status_code == 400


def test_logout_hands_account_hub_session_to_global_logout(monkeypatch):
    client = app.test_client()
    with app.app_context():
        ensure_account_hub_user(f'{PREFIX}logout')
    client.get('/login')
    state = _state(client)
    monkeypatch.setattr(AccountHubClient, 'exchange_code', lambda self, code: ('access', 'refresh'))
    monkeypatch.setattr(
        AccountHubClient,
        'check_tokens',
        lambda self, access, refresh: _claims(f'{PREFIX}logout', 123),
    )
    assert client.get(f'/auth/account-hub/callback?code=code&state={state}').status_code == 302
    response = client.get('/logout')
    assert response.status_code == 200
    assert b'https://hub.example/logout' in response.data
    with client.session_transaction() as session:
        assert not session

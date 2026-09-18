from unittest.mock import Mock

import pytest

from app import app
from auth.store import (
    AUTH_SOURCE_ACCOUNT_HUB,
    AUTH_SOURCE_LOCAL,
    ROLE_ADMIN,
    ROLE_SUB_ADMIN,
    ensure_account_hub_user,
    ensure_bootstrap_user,
    upsert_user,
)
from core.database import get_web_database
from integrations.account_hub import AccountHubInvalid, AccountHubClient


PREFIX = 'account-hub-test-'


@pytest.fixture(autouse=True)
def account_hub_config(monkeypatch):
    values = {
        'ACCOUNT_HUB_ENABLED': True,
        'ACCOUNT_HUB_LOGIN_URL': 'https://hub.example/auth/user/oauth/login',
        'ACCOUNT_HUB_TOKEN_CHECK_URL': 'https://hub.example/check',
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


def _claims(username='alice', uid=42, permissions=None, role_names=None):
    return {
        'uid': str(uid),
        'username': username,
        'email': f'{username}@example.com',
        'permissions': set(permissions or ()),
        'role_names': {'CVE_SYSTEM'} if role_names is None else set(role_names),
    }


def test_password_login_creates_user_with_default_local_role(monkeypatch):
    client = app.test_client()
    begin = client.get('/login?next=/settings')
    assert begin.status_code == 200
    assert b'name="username"' in begin.data
    monkeypatch.setattr(AccountHubClient, 'login', lambda self, username, password, captcha: ('access', 'refresh'))
    monkeypatch.setattr(
        AccountHubClient,
        'check_tokens',
        lambda self, access, refresh: _claims(
            f'{PREFIX}alice', 42, {'portal:sub-admin'},
        ),
    )
    logged_in = client.post('/login', data={
        'username': f'{PREFIX}alice', 'password': 'remote-password', 'next': '/settings',
    })
    assert logged_in.status_code == 302
    assert logged_in.headers['Location'].endswith('/settings')
    with client.session_transaction() as session:
        assert session['auth_method'] == AUTH_SOURCE_ACCOUNT_HUB
        assert session['username'] == f'{PREFIX}alice'

    with app.app_context():
        user = get_web_database()['auth'].find_one({'username': f'{PREFIX}alice'})
        assert user['account_hub_uid'] == '42'
        assert user['role'] == 'user'
    monkeypatch.setattr(AccountHubClient, 'check_tokens', Mock(side_effect=AssertionError('unexpected remote call')))
    assert client.get('/settings').status_code == 200


def test_user_without_cve_system_role_is_rejected(monkeypatch):
    client = app.test_client()
    monkeypatch.setattr(AccountHubClient, 'login', lambda self, username, password, captcha: ('access', 'refresh'))
    monkeypatch.setattr(
        AccountHubClient,
        'check_tokens',
        lambda self, access, refresh: _claims(f'{PREFIX}unknown', 999, role_names={'OTHER'}),
    )
    response = client.post('/login', data={'username': f'{PREFIX}unknown', 'password': 'password'})
    assert response.status_code == 403
    assert b'CVE_SYSTEM' in response.data
    with app.app_context():
        assert get_web_database()['auth'].find_one({'username': f'{PREFIX}unknown'}) is None


def test_remote_rejection_blocks_login_without_creating_user(monkeypatch):
    monkeypatch.setattr(AccountHubClient, 'login', Mock(side_effect=AccountHubInvalid('Invalid Account Hub username, password, or CAPTCHA.')))
    client = app.test_client()
    response = client.post('/login', data={'username': f'{PREFIX}wrong', 'password': 'wrong'})
    assert response.status_code == 401
    with app.app_context():
        assert get_web_database()['auth'].find_one({'username': f'{PREFIX}wrong'}) is None


def test_local_admin_can_assign_and_revoke_sub_admin_role(monkeypatch):
    username = f'{PREFIX}role-assignment'
    monkeypatch.setattr(AccountHubClient, 'login', lambda self, name, password, captcha: ('access', 'refresh'))
    monkeypatch.setattr(AccountHubClient, 'check_tokens', lambda self, access, refresh: _claims(username, 721))
    member = app.test_client()
    assert member.post('/login', data={'username': username, 'password': 'password'}).status_code == 302
    assert member.get('/admin/account-users').status_code == 403
    admin = app.test_client()
    _bootstrap_session(admin)
    users = admin.get('/api/admin/account-users').get_json()['data']
    item = next(user for user in users if user['username'] == username)
    assert item['role'] == 'user'
    update_url = f"/api/admin/account-users/{item['id']}"
    assert admin.put(update_url, json={'role': 'admin'}).status_code == 400
    assert admin.put(update_url, json={'role': 'sub_admin'}).status_code == 200
    assert member.get('/api/admin/account-users').status_code == 403
    with app.app_context():
        assert get_web_database()['auth'].find_one({'username': username})['role'] == 'sub_admin'
    assert member.get('/settings').status_code == 200
    assert admin.put(update_url, json={'role': 'user'}).status_code == 200
    assert member.get('/admin/account-users').status_code == 403


def test_account_hub_cannot_auto_approve_a_legacy_local_user(monkeypatch):
    username = f'{PREFIX}legacy-local'
    with app.app_context():
        upsert_user(username, 'local-password', auth_source=AUTH_SOURCE_LOCAL)
    client = app.test_client()
    monkeypatch.setattr(AccountHubClient, 'login', lambda self, username, password, captcha: ('access', 'refresh'))
    monkeypatch.setattr(
        AccountHubClient,
        'check_tokens',
        lambda self, access, refresh: _claims(username, 1001),
    )
    response = client.post('/login', data={'username': username, 'password': 'remote-password'})
    assert response.status_code == 403
    with app.app_context():
        user = get_web_database()['auth'].find_one({'username': username})
        assert user['auth_source'] == AUTH_SOURCE_LOCAL


def test_account_hub_allowlist_cannot_retain_a_top_admin_role():
    username = f'{PREFIX}stale-hub-admin'
    with app.app_context():
        auth = get_web_database()['auth']
        auth.insert_one({
            'username': username,
            'username_key': username.casefold(),
            'auth_source': AUTH_SOURCE_ACCOUNT_HUB,
            'role': ROLE_ADMIN,
            'password': 'stale',
        })
        user = ensure_account_hub_user(username)
    assert user['role'] == 'user'
    with app.app_context():
        stored = get_web_database()['auth'].find_one({'username': username})
    assert stored['role'] == 'user'
    assert 'password' not in stored


def test_account_hub_user_cannot_access_top_admin_configuration(monkeypatch):
    client = app.test_client()
    monkeypatch.setattr(AccountHubClient, 'login', lambda self, username, password, captcha: ('access', 'refresh'))
    monkeypatch.setattr(
        AccountHubClient,
        'check_tokens',
        lambda self, access, refresh: _claims(
            f'{PREFIX}delegated', 4242, {'portal:admin'},
        ),
    )
    assert client.post('/login', data={'username': f'{PREFIX}delegated', 'password': 'password'}).status_code == 302
    response = client.get('/admin/account-users')
    assert response.status_code == 403
    assert client.get('/operations').status_code == 403
    assert client.get('/api/operations/newsletter-editor').status_code == 403
    assert client.put('/api/operations/newsletter-editor', json={}).status_code == 403
    assert client.post('/set-news', json={}).status_code == 403
    assert client.post('/api/reports/evidence-cache/purge').status_code == 403
    assert client.post('/api/reports/search-cache/purge').status_code == 403
    with app.app_context():
        user = get_web_database()['auth'].find_one({'username': f'{PREFIX}delegated'})
        assert user['role'] == 'user'


def test_local_bootstrap_can_sign_in_and_remains_top_admin(monkeypatch):
    username = f'{PREFIX}local-admin'
    with app.app_context():
        upsert_user(username, 'local-password', role=ROLE_ADMIN, auth_source=AUTH_SOURCE_LOCAL)
    monkeypatch.setitem(app.config, 'WEB_AUTH_BOOTSTRAP_USERNAME', username)
    client = app.test_client()
    response = client.post('/login/local', data={
        'username': username,
        'password': 'local-password',
    })
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session['auth_method'] == AUTH_SOURCE_LOCAL
    assert client.get('/admin/account-users').status_code == 200


def test_account_hub_cannot_replace_local_bootstrap_identity():
    username = f'{PREFIX}reserved-admin'
    with app.app_context():
        upsert_user(username, 'local-password', role=ROLE_ADMIN, auth_source=AUTH_SOURCE_LOCAL)
        with pytest.raises(ValueError, match='reserved for the local administrator'):
            ensure_account_hub_user(username)


def test_bootstrap_username_is_reserved_even_before_a_local_row_exists():
    with app.app_context():
        with pytest.raises(ValueError, match='reserved for the local administrator'):
            ensure_account_hub_user(app.config['WEB_AUTH_BOOTSTRAP_USERNAME'])


def test_bootstrap_startup_never_promotes_a_matching_account_hub_row(monkeypatch):
    username = f'{PREFIX}hub-collision'
    with app.app_context():
        get_web_database()['auth'].insert_one({
            'username': username,
            'username_key': username.casefold(),
            'auth_source': AUTH_SOURCE_ACCOUNT_HUB,
            'role': 'user',
            'disabled': False,
            'pause_managed_subscriptions_when_disabled': False,
            'must_change_password': False,
        })
        monkeypatch.setitem(app.config, 'WEB_AUTH_BOOTSTRAP_USERNAME', username)
        ensure_bootstrap_user(app.config)
        user = get_web_database()['auth'].find_one({'username': username})
    assert user['auth_source'] == AUTH_SOURCE_ACCOUNT_HUB
    assert user['role'] == 'user'


def test_bootstrap_startup_repairs_the_configured_local_record(monkeypatch):
    username = f'{PREFIX}local-repair'
    with app.app_context():
        upsert_user(username, 'local-password', role='user', auth_source=AUTH_SOURCE_LOCAL)
        monkeypatch.setitem(app.config, 'WEB_AUTH_BOOTSTRAP_USERNAME', username)
        ensure_bootstrap_user(app.config)
        user = get_web_database()['auth'].find_one({'username': username})
    assert user['auth_source'] == AUTH_SOURCE_LOCAL
    assert user['role'] == ROLE_ADMIN
    assert user['disabled'] is False


def test_bootstrap_startup_does_not_guess_another_local_admin(monkeypatch):
    username = f'{PREFIX}missing-bootstrap'
    other = f'{PREFIX}unrelated-admin'
    with app.app_context():
        upsert_user(other, 'local-password', role=ROLE_ADMIN, auth_source=AUTH_SOURCE_LOCAL)
        monkeypatch.setitem(app.config, 'WEB_AUTH_BOOTSTRAP_USERNAME', username)
        monkeypatch.setitem(app.config, 'WEB_AUTH_BOOTSTRAP_PASSWORD', '')
        assert ensure_bootstrap_user(app.config) is False
        user = get_web_database()['auth'].find_one({'username': other})
    assert user['role'] == ROLE_ADMIN
    assert user['username'] == other


def test_enabling_account_hub_does_not_silently_migrate_local_users():
    username = f'{PREFIX}legacy-local'
    with app.app_context():
        upsert_user(username, 'local-password', role='user', auth_source=AUTH_SOURCE_LOCAL)
        ensure_bootstrap_user(app.config)
        user = get_web_database()['auth'].find_one({'username': username})
    assert user['auth_source'] == AUTH_SOURCE_LOCAL
    assert user['role'] == 'user'


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
    with app.app_context():
        ensure_account_hub_user(
            f'{PREFIX}subscriber',
            f'{PREFIX}subscriber@example.com',
        )
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


def test_account_hub_subscription_creation_requires_allowlist_approval():
    client = app.test_client()
    _bootstrap_session(client)
    response = client.post('/api/subscriptions', json={
        'username': f'{PREFIX}not-approved',
        'emails': [f'{PREFIX}not-approved@example.com'],
        'team': 'Account Hub',
        'newsletter_profile': {'enabled': False, 'filters': {}},
        'report_profile': {'enabled': False, 'filters': {}},
    })
    assert response.status_code == 400
    assert b'must be approved' in response.data
    with app.app_context():
        assert get_web_database()['auth'].find_one({
            'username': f'{PREFIX}not-approved',
        }) is None


def test_account_hub_subscription_cannot_rename_approved_owner_to_unknown_user():
    from auth.store import ensure_subscription_user, find_user

    username = f'{PREFIX}approved-owner'
    with app.app_context():
        approved = ensure_account_hub_user(username)
        with pytest.raises(ValueError, match='approved before changing its username'):
            ensure_subscription_user(
                f'{PREFIX}not-approved',
                user_id=approved['_id'],
            )
        stored = find_user(username)
        assert stored['_id'] == approved['_id']


def test_logout_clears_local_account_hub_session(monkeypatch):
    client = app.test_client()
    monkeypatch.setattr(AccountHubClient, 'login', lambda self, username, password, captcha: ('access', 'refresh'))
    monkeypatch.setattr(
        AccountHubClient,
        'check_tokens',
        lambda self, access, refresh: _claims(f'{PREFIX}logout', 123),
    )
    assert client.post('/login', data={'username': f'{PREFIX}logout', 'password': 'password'}).status_code == 302
    response = client.get('/logout')
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert not session

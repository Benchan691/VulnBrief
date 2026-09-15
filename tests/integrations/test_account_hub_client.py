from unittest.mock import Mock

import pytest

from integrations.account_hub import (
    AccountHubClient,
    AccountHubInvalid,
    AccountHubMisconfigured,
    AccountHubSessionStore,
)


CONFIG = {
    'ACCOUNT_HUB_AUTHORIZE_URL': 'https://hub.example/auth/oauth2/authorize',
    'ACCOUNT_HUB_TOKEN_URL': 'https://hub.example/auth/oauth2/token',
    'ACCOUNT_HUB_TOKEN_CHECK_URL': 'https://hub.example/auth/open-api/v1/token/check',
    'ACCOUNT_HUB_LOGOUT_URL': 'https://hub.example/auth/user/oauth/logout',
    'ACCOUNT_HUB_CLIENT_ID': 'portal-client',
    'ACCOUNT_HUB_CLIENT_SECRET': 'client-secret',
    'ACCOUNT_HUB_REDIRECT_URI': 'https://portal.example/auth/account-hub/callback',
    'ACCOUNT_HUB_SCOPE': 'openid',
    'ACCOUNT_HUB_ADMIN_PERMISSION': 'portal:admin',
    'ACCOUNT_HUB_SUB_ADMIN_PERMISSION': 'portal:sub-admin',
    'ACCOUNT_HUB_TIMEOUT_SECONDS': 3,
}


def response(status_code=200, payload=None):
    result = Mock()
    result.status_code = status_code
    result.json.return_value = payload if payload is not None else {}
    return result


def test_authorization_url_contains_registered_redirect_and_state():
    url = AccountHubClient(CONFIG).authorization_url('random-state')
    assert url.startswith(CONFIG['ACCOUNT_HUB_AUTHORIZE_URL'] + '?')
    assert 'client_id=portal-client' in url
    assert 'redirect_uri=https%3A%2F%2Fportal.example%2Fauth%2Faccount-hub%2Fcallback' in url
    assert 'scope=openid' in url
    assert 'state=random-state' in url


def test_exchange_and_check_parse_wrapped_account_hub_payload(monkeypatch):
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        if method == 'POST':
            return response(200, {
                'code': 0,
                'data': {'accessToken': 'access', 'refreshToken': 'refresh'},
            })
        return response(200, {
            'code': 0,
            'data': {
                'uid': 42,
                'username': 'alice',
                'email': 'alice@example.com',
                'roles': [{'permissions': [{'permissionName': 'portal:admin'}]}],
                'authorities': [{'authority': 'portal:read'}],
                'accountNonExpired': True,
                'credentialsNonExpired': True,
                'accountNonLocked': True,
                'enabled': True,
            },
        })

    monkeypatch.setattr('integrations.account_hub.requests.request', fake_request)
    client = AccountHubClient(CONFIG)
    assert client.exchange_code('code') == ('access', 'refresh')
    claims = client.check_tokens('access', 'refresh')
    assert claims['uid'] == '42'
    assert claims['username'] == 'alice'
    assert claims['permissions'] == {'portal:admin', 'portal:read'}
    assert calls[0][2]['data']['grant_type'] == 'authorization_code'
    assert calls[1][2]['params'] == {'accessToken': 'access', 'refreshToken': 'refresh'}


def test_check_rejects_inactive_or_non_success_sessions(monkeypatch):
    monkeypatch.setattr(
        'integrations.account_hub.requests.request',
        lambda *args, **kwargs: response(200, {
            'code': 0,
            'data': {
                'uid': 42,
                'username': 'alice',
                'enabled': False,
            },
        }),
    )
    with pytest.raises(AccountHubInvalid):
        AccountHubClient(CONFIG).check_tokens('access', 'refresh')

    monkeypatch.setattr(
        'integrations.account_hub.requests.request',
        lambda *args, **kwargs: response(200, {'code': 500, 'data': {}}),
    )
    with pytest.raises(AccountHubInvalid):
        AccountHubClient(CONFIG).check_tokens('access', 'refresh')


def test_client_requires_all_registered_endpoints():
    incomplete = dict(CONFIG)
    incomplete['ACCOUNT_HUB_CLIENT_SECRET'] = ''
    with pytest.raises(AccountHubMisconfigured):
        AccountHubClient(incomplete).authorization_url('state')


def test_session_store_keeps_tokens_process_local():
    store = AccountHubSessionStore()
    session_id = store.create('access', 'refresh', 'user-id')
    stored = store.get(session_id)
    assert stored.access_token == 'access'
    assert stored.refresh_token == 'refresh'
    assert stored.user_id == 'user-id'
    store.remove(session_id)
    assert store.get(session_id) is None

from unittest.mock import Mock
import base64

import pytest

from integrations.account_hub import (
    AccountHubClient,
    AccountHubInvalid,
    AccountHubMisconfigured,
)


CONFIG = {
    'ACCOUNT_HUB_LOGIN_URL': 'https://hub.example/auth/user/oauth/login',
    'ACCOUNT_HUB_TOKEN_CHECK_URL': 'https://hub.example/auth/open-api/v1/token/check',
    'ACCOUNT_HUB_TIMEOUT_SECONDS': 3,
}


def response(status_code=200, payload=None):
    result = Mock()
    result.status_code = status_code
    result.json.return_value = payload if payload is not None else {}
    return result


def test_check_parses_wrapped_account_hub_payload(monkeypatch):
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return response(200, {
            'code': 0,
            'data': {
                'uid': 42,
                'username': 'alice',
                'email': 'alice@example.com',
                'roles': [{'roleName': 'CVE_SYSTEM', 'permissions': [{'permissionName': 'portal:admin'}]}],
                'authorities': [{'authority': 'portal:read'}],
                'accountNonExpired': True,
                'credentialsNonExpired': True,
                'accountNonLocked': True,
                'enabled': True,
            },
        })

    monkeypatch.setattr('integrations.account_hub.requests.request', fake_request)
    client = AccountHubClient(CONFIG)
    claims = client.check_tokens('access', 'refresh')
    assert claims['uid'] == '42'
    assert claims['username'] == 'alice'
    assert claims['role_names'] == {'CVE_SYSTEM'}
    assert calls[0][2]['params'] == {'accessToken': 'access', 'refreshToken': 'refresh'}


def test_password_login_base64_encodes_password_and_passes_optional_captcha(monkeypatch):
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return response(200, {'code': 0, 'data': {'accessToken': 'access', 'refreshToken': 'refresh'}})

    monkeypatch.setattr('integrations.account_hub.requests.request', fake_request)
    client = AccountHubClient(CONFIG)
    assert client.login('alice', 'päss') == ('access', 'refresh')
    assert calls[0][0:2] == ('POST', CONFIG['ACCOUNT_HUB_LOGIN_URL'])
    assert calls[0][2]['data']['password'] == base64.b64encode('päss'.encode()).decode()
    assert 'captchaVerification' not in calls[0][2]['data']
    client.login('alice', 'päss', 'slider-token')
    assert calls[1][2]['data']['captchaVerification'] == 'slider-token'


def test_password_login_rejects_bad_credentials_or_business_failure(monkeypatch):
    monkeypatch.setattr('integrations.account_hub.requests.request', lambda *args, **kwargs: response(401))
    with pytest.raises(AccountHubInvalid):
        AccountHubClient(CONFIG).login('alice', 'wrong')
    monkeypatch.setattr('integrations.account_hub.requests.request', lambda *args, **kwargs: response(200, {'code': 401}))
    with pytest.raises(AccountHubInvalid):
        AccountHubClient(CONFIG).login('alice', 'wrong')


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


def test_client_requires_login_and_check_endpoints():
    incomplete = dict(CONFIG)
    incomplete['ACCOUNT_HUB_LOGIN_URL'] = ''
    with pytest.raises(AccountHubMisconfigured):
        AccountHubClient(incomplete).login('alice', 'password')

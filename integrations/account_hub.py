"""Account Hub password login and token-check client."""

import base64

import requests


class AccountHubError(Exception):
    """Base error for expected Account Hub failures."""


class AccountHubInvalid(AccountHubError):
    """The credentials, login response, or token is invalid."""


class AccountHubUnavailable(AccountHubError):
    """Account Hub could not be reached or returned an invalid service response."""


class AccountHubMisconfigured(AccountHubError):
    """The deployment has not supplied the Account Hub settings."""


class AccountHubClient:
    REQUIRED_SETTINGS = (
        'ACCOUNT_HUB_LOGIN_URL',
        'ACCOUNT_HUB_TOKEN_CHECK_URL',
    )

    def __init__(self, config):
        self.config = config

    @property
    def timeout(self):
        try:
            return max(float(self.config.get('ACCOUNT_HUB_TIMEOUT_SECONDS') or 5), 1)
        except (TypeError, ValueError) as exc:
            raise AccountHubMisconfigured(
                'ACCOUNT_HUB_TIMEOUT_SECONDS must be a number.',
            ) from exc

    def _settings(self):
        missing = [
            key for key in self.REQUIRED_SETTINGS
            if not str(self.config.get(key) or '').strip()
        ]
        if missing:
            raise AccountHubMisconfigured(
                'Account Hub is not configured: ' + ', '.join(missing),
            )
        return self.config

    @staticmethod
    def _json(response):
        try:
            payload = response.json()
        except (TypeError, ValueError) as exc:
            raise AccountHubUnavailable('Account Hub returned invalid JSON.') from exc
        if not isinstance(payload, dict):
            raise AccountHubUnavailable('Account Hub returned an invalid response.')
        return payload

    @staticmethod
    def _data(payload):
        data = payload.get('data')
        if isinstance(data, dict):
            return data
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _ensure_success_payload(payload, message):
        """Reject non-success business envelopes even when HTTP status is 200."""
        code = payload.get('code')
        if code in (None, 0, 200, '0', '200'):
            return
        raise AccountHubInvalid(message)

    def _request(self, method, url, **kwargs):
        try:
            return requests.request(method, url, timeout=self.timeout, **kwargs)
        except requests.RequestException as exc:
            raise AccountHubUnavailable('Account Hub is unavailable.') from exc

    def login(self, username, password, captcha_verification=''):
        """Authenticate with the documented password endpoint; never log credentials."""
        config = self._settings()
        fields = {
            'username': username,
            'password': base64.b64encode(password.encode('utf-8')).decode('ascii'),
        }
        if captcha_verification:
            fields['captchaVerification'] = captcha_verification
        response = self._request(
            'POST', config['ACCOUNT_HUB_LOGIN_URL'], data=fields,
            headers={'Accept': 'application/json'},
        )
        if response.status_code in {400, 401, 403}:
            raise AccountHubInvalid('Invalid Account Hub username, password, or CAPTCHA.')
        if response.status_code >= 500:
            raise AccountHubUnavailable('Account Hub is unavailable.')
        if response.status_code != 200:
            raise AccountHubInvalid('Invalid Account Hub username, password, or CAPTCHA.')
        payload = self._json(response)
        self._ensure_success_payload(payload, 'Invalid Account Hub username, password, or CAPTCHA.')
        data = self._data(payload)
        access_token = data.get('accessToken') or data.get('access_token')
        refresh_token = data.get('refreshToken') or data.get('refresh_token')
        if not isinstance(access_token, str) or not access_token or not isinstance(refresh_token, str) or not refresh_token:
            raise AccountHubInvalid('Account Hub did not return usable tokens.')
        return access_token, refresh_token

    def check_tokens(self, access_token, refresh_token):
        config = self._settings()
        response = self._request(
            'GET',
            config['ACCOUNT_HUB_TOKEN_CHECK_URL'],
            params={'accessToken': access_token, 'refreshToken': refresh_token},
            headers={'Accept': 'application/json'},
        )
        if response.status_code in {401, 404, 500}:
            raise AccountHubInvalid('Account Hub session is no longer valid.')
        if response.status_code >= 500:
            raise AccountHubUnavailable('Account Hub token service is unavailable.')
        if response.status_code != 200:
            raise AccountHubInvalid('Account Hub session is no longer valid.')
        payload = self._json(response)
        self._ensure_success_payload(payload, 'Account Hub session is no longer valid.')
        data = self._data(payload)
        uid = data.get('uid')
        username = data.get('username')
        if uid in (None, '') or not isinstance(username, str) or not username.strip():
            raise AccountHubInvalid('Account Hub returned incomplete user information.')
        for field in ('accountNonExpired', 'credentialsNonExpired', 'accountNonLocked', 'enabled'):
            if field in data and data[field] is not True:
                raise AccountHubInvalid('Account Hub account is not active.')
        if 'anonymousFlag' in data and data['anonymousFlag'] is not False:
            raise AccountHubInvalid('Anonymous Account Hub sessions are not allowed.')
        role_names = set()
        for role in data.get('roles') or []:
            if not isinstance(role, dict):
                continue
            if isinstance(role.get('roleName'), str) and role['roleName'].strip():
                role_names.add(role['roleName'].strip())
        return {
            'uid': str(uid),
            'username': username.strip(),
            'email': str(data.get('email') or '').strip(),
            'role_names': role_names,
        }

"""Small Account Hub OAuth client and process-local token session store."""

from dataclasses import dataclass
from threading import RLock
import secrets
import time
from urllib.parse import urlencode

import requests


class AccountHubError(Exception):
    """Base error for expected Account Hub failures."""


class AccountHubInvalid(AccountHubError):
    """The authorization response or token is invalid."""


class AccountHubUnavailable(AccountHubError):
    """Account Hub could not be reached or returned an invalid service response."""


class AccountHubMisconfigured(AccountHubError):
    """The deployment has not supplied the Account Hub settings."""


@dataclass(frozen=True)
class AccountHubTokenSession:
    access_token: str
    refresh_token: str
    user_id: str
    created_at: float


class AccountHubSessionStore:
    """In-memory token storage for the application's single Gunicorn worker."""

    def __init__(self):
        self._sessions = {}
        self._lock = RLock()

    def create(self, access_token, refresh_token, user_id):
        if not access_token or not refresh_token or not user_id:
            raise ValueError('Account Hub token session is incomplete.')
        session_id = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[session_id] = AccountHubTokenSession(
                access_token=access_token,
                refresh_token=refresh_token,
                user_id=str(user_id),
                created_at=time.monotonic(),
            )
        return session_id

    def get(self, session_id):
        if not session_id:
            return None
        with self._lock:
            return self._sessions.get(session_id)

    def remove(self, session_id):
        if not session_id:
            return
        with self._lock:
            self._sessions.pop(session_id, None)


SESSION_STORE = AccountHubSessionStore()


class AccountHubClient:
    REQUIRED_SETTINGS = (
        'ACCOUNT_HUB_AUTHORIZE_URL',
        'ACCOUNT_HUB_TOKEN_URL',
        'ACCOUNT_HUB_TOKEN_CHECK_URL',
        'ACCOUNT_HUB_LOGOUT_URL',
        'ACCOUNT_HUB_CLIENT_ID',
        'ACCOUNT_HUB_CLIENT_SECRET',
        'ACCOUNT_HUB_REDIRECT_URI',
        'ACCOUNT_HUB_ADMIN_PERMISSION',
        'ACCOUNT_HUB_SUB_ADMIN_PERMISSION',
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

    def authorization_url(self, state):
        config = self._settings()
        query = urlencode({
            'response_type': 'code',
            'client_id': config['ACCOUNT_HUB_CLIENT_ID'],
            'redirect_uri': config['ACCOUNT_HUB_REDIRECT_URI'],
            'scope': config.get('ACCOUNT_HUB_SCOPE') or 'openid',
            'state': state,
        })
        separator = '&' if '?' in config['ACCOUNT_HUB_AUTHORIZE_URL'] else '?'
        return config['ACCOUNT_HUB_AUTHORIZE_URL'] + separator + query

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

    def exchange_code(self, code):
        config = self._settings()
        response = self._request(
            'POST',
            config['ACCOUNT_HUB_TOKEN_URL'],
            data={
                'client_id': config['ACCOUNT_HUB_CLIENT_ID'],
                'client_secret': config['ACCOUNT_HUB_CLIENT_SECRET'],
                'grant_type': 'authorization_code',
                'redirect_uri': config['ACCOUNT_HUB_REDIRECT_URI'],
                'code': code,
            },
            headers={'Accept': 'application/json'},
        )
        if response.status_code in {401, 403}:
            raise AccountHubInvalid('Account Hub authorization code was rejected.')
        if response.status_code >= 500:
            raise AccountHubUnavailable('Account Hub token service is unavailable.')
        if response.status_code != 200:
            raise AccountHubInvalid('Account Hub authorization code was rejected.')
        payload = self._json(response)
        self._ensure_success_payload(payload, 'Account Hub authorization code was rejected.')
        data = self._data(payload)
        access_token = data.get('accessToken') or data.get('access_token')
        refresh_token = data.get('refreshToken') or data.get('refresh_token')
        if not isinstance(access_token, str) or not isinstance(refresh_token, str):
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
        permissions = set()
        for role in data.get('roles') or []:
            if not isinstance(role, dict):
                continue
            for permission in role.get('permissions') or []:
                if isinstance(permission, dict) and permission.get('permissionName'):
                    permissions.add(str(permission['permissionName']).strip())
                elif isinstance(permission, str) and permission.strip():
                    permissions.add(permission.strip())
        for authority in data.get('authorities') or []:
            if isinstance(authority, dict) and authority.get('authority'):
                permissions.add(str(authority['authority']).strip())
            elif isinstance(authority, str) and authority.strip():
                permissions.add(authority.strip())
        return {
            'uid': str(uid),
            'username': username.strip(),
            'email': str(data.get('email') or '').strip(),
            'permissions': permissions,
            'raw': data,
        }

    def global_logout_url(self):
        return self._settings()['ACCOUNT_HUB_LOGOUT_URL']

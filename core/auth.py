from functools import wraps

from flask import current_app, g, jsonify, redirect, render_template, request, session, url_for
from pymongo.errors import PyMongoError

from auth.store import (
    AUTH_SOURCE_ACCOUNT_HUB,
    AUTH_SOURCE_LOCAL,
    ADMIN_ROLES,
    ROLE_ADMIN,
    find_user,
    find_user_by_id,
    is_local_bootstrap_user,
)
from core.i18n import t
from integrations.account_hub import (
    AccountHubMisconfigured,
    AccountHubUnavailable,
)


def current_user():
    if getattr(g, '_auth_checked', False):
        return getattr(g, 'current_user', None)
    g._auth_checked = True
    try:
        user_id = session.get('user_id')
        session_username = session.get('username')
    except RuntimeError:
        return None
    user = None
    if session.get('auth_method') == AUTH_SOURCE_ACCOUNT_HUB:
        if not current_app.config.get('ACCOUNT_HUB_ENABLED'):
            _clear_session()
            return None
        hub_uid = session.get('account_hub_uid')
        if not user_id or not hub_uid:
            _clear_session()
            return None
        try:
            user = find_user_by_id(user_id)
        except (PyMongoError, RuntimeError):
            _clear_session()
            return None
        if (
            user is None or user.get('disabled')
            or user.get('auth_source') != AUTH_SOURCE_ACCOUNT_HUB
            or str(user.get('account_hub_uid') or '') != str(hub_uid)
            or user.get('role') not in {'user', 'sub_admin'}
        ):
            _clear_session()
            return None
        session['username'] = user.get('username') or ''
        g.current_user = user
        return user
    if user_id:
        try:
            user = find_user_by_id(user_id)
        except (PyMongoError, RuntimeError):
            return None
    if user is None and session_username:
        try:
            user = find_user(session_username)
        except (PyMongoError, RuntimeError):
            return None
        if user is not None and user.get('_id') is not None:
            session['user_id'] = str(user['_id'])

    if user is None:
        session.pop('user_id', None)
        session.pop('username', None)
        return None
    if user.get('disabled'):
        session.pop('user_id', None)
        session.pop('username', None)
        return None

    # Once SSO is enabled, the only local session that remains valid is the
    # configured break-glass administrator. This also expires cookies created
    # by the legacy local-login flow before Account Hub was enabled.
    if current_app.config.get('ACCOUNT_HUB_ENABLED'):
        if not is_local_bootstrap_user(user):
            _clear_session()
            return None

    session['username'] = user.get('username') or ''
    g.current_user = user
    return user


def _clear_session():
    session.clear()


def _json_request():
    return request.path.startswith('/api/')


def _unauthenticated():
    if _json_request():
        return jsonify({'error': 'Authentication required'}), 401
    if current_app.config.get('ACCOUNT_HUB_ENABLED'):
        return redirect(url_for('auth.login', next=request.full_path))
    return redirect(url_for('auth.login'))


def _auth_unavailable():
    if _json_request():
        return jsonify({'error': 'Authentication service unavailable'}), 503
    return render_template(
        'auth/login.html',
        error=t('Authentication service unavailable. Please try again.'),
    ), 503


def _forbidden(message='Administrator access required.'):
    if _json_request():
        return jsonify({'error': message}), 403
    return render_template('errors/403.html'), 403


def _guarded_user(*, allow_password_change=False):
    try:
        user = current_user()
    except AccountHubMisconfigured:
        return None, _auth_unavailable()
    except AccountHubUnavailable:
        return None, _auth_unavailable()
    if user is None:
        return None, _unauthenticated()
    if user.get('must_change_password') and not allow_password_change:
        if _json_request():
            return None, (jsonify({
                'error': 'Password change required.',
                'code': 'password_change_required',
            }), 403)
        return None, redirect(url_for('auth.settings'))
    g.current_user = user
    return user, None


def login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        user, response = _guarded_user(
            allow_password_change=request.endpoint in {
                'auth.settings',
                'auth.change_password',
                'auth.logout',
            },
        )
        if response is not None:
            return response
        return function(*args, **kwargs)

    return decorated_function


def local_admin_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        user, response = _guarded_user(allow_password_change=True)
        if response is not None:
            return response
        if not is_top_admin(user):
            return _forbidden('Local administrator access required.')
        return function(*args, **kwargs)

    return decorated_function


def admin_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        user, response = _guarded_user()
        if response is not None:
            return response
        if not is_admin(user):
            return _forbidden()
        return function(*args, **kwargs)

    return decorated_function


def is_admin(user=None):
    if user is None:
        try:
            user = current_user()
        except (AccountHubMisconfigured, AccountHubUnavailable):
            return False
    if not user or user.get('role') not in ADMIN_ROLES:
        return False
    if user.get('role') == ROLE_ADMIN:
        return is_top_admin(user)
    return True


def is_top_admin(user=None):
    if user is None:
        try:
            user = current_user()
        except (AccountHubMisconfigured, AccountHubUnavailable):
            return False
    if not user or user.get('role') != ROLE_ADMIN:
        return False
    # A stale or forged non-local row must never be treated as the portal's
    # top administrator, even while SSO is disabled for maintenance.
    if user.get('auth_source') not in (None, AUTH_SOURCE_LOCAL):
        return False
    if current_app.config.get('ACCOUNT_HUB_ENABLED'):
        return is_local_bootstrap_user(user)
    return True


def top_admin_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        user, response = _guarded_user()
        if response is not None:
            return response
        if not is_top_admin(user):
            return _forbidden('Top-level administrator access required.')
        return function(*args, **kwargs)

    return decorated_function


def admin_data_scope(user=None):
    """Return the server-side ownership filter for admin-managed records."""
    user = user if user is not None else current_user()
    if is_top_admin(user):
        return {}
    if user and user.get('role') in ADMIN_ROLES and user.get('_id') is not None:
        return {'managed_by_user_id': user['_id']}
    return {'_id': None}


def scoped_admin_query(query=None, user=None):
    query = dict(query or {})
    scope = admin_data_scope(user)
    if not scope:
        return query
    if not query:
        return scope
    return {'$and': [query, scope]}

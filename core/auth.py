from functools import wraps

from flask import g, jsonify, redirect, render_template, request, session, url_for
from pymongo.errors import PyMongoError

from auth.store import find_user, find_user_by_id, ROLE_ADMIN


def current_user():
    try:
        user_id = session.get('user_id')
        session_username = session.get('username')
    except RuntimeError:
        return None
    user = None
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

    session['username'] = user.get('username') or ''
    return user


def _json_request():
    return request.path.startswith('/api/')


def _unauthenticated():
    if _json_request():
        return jsonify({'error': 'Authentication required'}), 401
    return redirect(url_for('auth.login'))


def _forbidden(message='Administrator access required.'):
    if _json_request():
        return jsonify({'error': message}), 403
    return render_template('errors/403.html'), 403


def _guarded_user(*, allow_password_change=False):
    user = current_user()
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


def admin_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        user, response = _guarded_user()
        if response is not None:
            return response
        if user.get('role') != ROLE_ADMIN:
            return _forbidden()
        return function(*args, **kwargs)

    return decorated_function


def is_admin(user=None):
    user = user if user is not None else current_user()
    return bool(user and user.get('role') == ROLE_ADMIN)

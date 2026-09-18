from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session, url_for
from pymongo.errors import PyMongoError

from auth.store import (
    AUTH_SOURCE_ACCOUNT_HUB,
    AUTH_SOURCE_LOCAL,
    create_sub_admin,
    ensure_account_hub_user,
    login_account_hub_user,
    list_sub_admins,
    list_account_hub_users,
    normalize_login,
    is_local_bootstrap_user,
    public_user,
    remove_sub_admin,
    update_sub_admin,
    update_account_hub_user,
    update_user_password,
    validate_email,
    verify_login,
    verify_password,
)
from core.auth import _clear_session, current_user, login_required, top_admin_required
from core.i18n import t
from integrations.account_hub import (
    AccountHubClient,
    AccountHubInvalid,
    AccountHubMisconfigured,
    AccountHubUnavailable,
)


auth_blueprint = Blueprint('auth', __name__)


def _sub_admin_public(user):
    result = public_user(user)
    for field in ('created_at', 'updated_at'):
        value = user.get(field)
        if value is not None and hasattr(value, 'isoformat'):
            result[field] = value.isoformat()
    return result


def _boolean_field(data, name):
    if name not in data:
        return None
    value = data.get(name)
    if not isinstance(value, bool):
        raise ValueError(f'{name} must be true or false.')
    return value


def _sub_admin_error(exc):
    message = str(exc)
    status = 409 if message in {'Username is already in use.', 'Email is already in use.'} else 400
    return jsonify({'error': t(message)}), status


def _account_hub_enabled():
    return bool(current_app.config.get('ACCOUNT_HUB_ENABLED'))


def _safe_next(value):
    value = value if isinstance(value, str) else ''
    if not value.startswith('/') or value.startswith('//'):
        return url_for('subscription.subscriptions')
    return value


def _account_hub_error(message, status=503):
    return render_template('auth/login.html', error=t(message)), status


def _account_user_public(user):
    result = public_user(user)
    for field in ('created_at', 'updated_at', 'last_account_hub_sync_at'):
        value = user.get(field)
        if value is not None and hasattr(value, 'isoformat'):
            result[field] = value.isoformat()
    result['role_source'] = 'local'
    return result


@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if _account_hub_enabled():
        if request.method == 'GET':
            return render_template('auth/login.html')
        username = normalize_login(request.form.get('username'))
        password = request.form.get('password') or ''
        if not username or not password:
            return _account_hub_error('Invalid username or password', 401)
        try:
            client = AccountHubClient(current_app.config)
            access_token, refresh_token = client.login(
                username, password, request.form.get('captchaVerification') or '',
            )
            claims = client.check_tokens(access_token, refresh_token)
            if 'CVE_SYSTEM' not in claims['role_names']:
                return _account_hub_error('CVE_SYSTEM role is required.', 403)
            user = login_account_hub_user(claims)
        except AccountHubInvalid as exc:
            return _account_hub_error(str(exc), 401)
        except AccountHubMisconfigured:
            return _account_hub_error('Account Hub is not configured.')
        except AccountHubUnavailable:
            return _account_hub_error('Account Hub is unavailable.')
        except ValueError as exc:
            return _account_hub_error(str(exc), 403)
        except PyMongoError:
            return _account_hub_error('Unable to establish the Account Hub session.')
        _clear_session()
        session.permanent = True
        session['auth_method'] = AUTH_SOURCE_ACCOUNT_HUB
        session['user_id'] = str(user['_id'])
        session['account_hub_uid'] = claims['uid']
        session['username'] = user['username']
        return redirect(_safe_next(request.form.get('next')))
    if request.method == 'POST':
        login_name = normalize_login(request.form.get('username'))
        password = request.form.get('password') or ''

        try:
            user = verify_login(login_name, password)
            if user is not None:
                _clear_session()
                session.permanent = True
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                if user.get('must_change_password'):
                    return redirect(url_for('auth.settings'))
                return redirect(url_for('subscription.subscriptions'))
            return render_template('auth/login.html', error=t('Invalid username or password'))
        except PyMongoError:
            return render_template(
                'auth/login.html',
                error=t('Unable to connect to the authentication database.'),
            ), 503

    return render_template('auth/login.html')


@auth_blueprint.route('/login/local', methods=['GET', 'POST'])
def local_login():
    if request.method == 'POST':
        login_name = normalize_login(request.form.get('username'))
        password = request.form.get('password') or ''
        try:
            user = verify_login(login_name, password)
            if user is not None and is_local_bootstrap_user(user):
                _clear_session()
                session.permanent = True
                session['auth_method'] = AUTH_SOURCE_LOCAL
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                return redirect(url_for('subscription.subscriptions'))
            return render_template('auth/login.html', local_login=True, error=t('Invalid username or password'))
        except PyMongoError:
            return render_template(
                'auth/login.html',
                local_login=True,
                error=t('Unable to connect to the authentication database.'),
            ), 503
    return render_template('auth/login.html', local_login=True)


@auth_blueprint.route('/auth/account-hub/callback')
def account_hub_callback():
    return redirect(url_for('auth.login'))


@auth_blueprint.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('auth.login'))


@auth_blueprint.route('/settings')
@login_required
def settings():
    return render_template('auth/settings.html')


@auth_blueprint.route('/admin/sub-admins')
@top_admin_required
def sub_admins():
    if _account_hub_enabled():
        return redirect(url_for('auth.account_users'))
    return render_template('auth/sub_admins_legacy.html')


@auth_blueprint.route('/admin/account-users')
@top_admin_required
def account_users():
    if not _account_hub_enabled():
        return redirect(url_for('auth.sub_admins'))
    return render_template('auth/sub_admins.html', account_hub_enabled=True)


@auth_blueprint.route('/api/admin/sub-admins')
@top_admin_required
def get_sub_admins():
    if _account_hub_enabled():
        return jsonify({'error': t('Account Hub user management has replaced sub-admin management.')}), 410
    try:
        return jsonify({'data': [_sub_admin_public(user) for user in list_sub_admins()]})
    except PyMongoError:
        return jsonify({'error': t('Unable to load sub-admins.')}), 503


@auth_blueprint.route('/api/admin/account-users')
@top_admin_required
def get_account_users():
    if not _account_hub_enabled():
        return jsonify({'error': t('Account Hub is disabled.')}), 410
    try:
        return jsonify({'data': [_account_user_public(user) for user in list_account_hub_users()]})
    except PyMongoError:
        return jsonify({'error': t('Unable to load Account Hub users.')}), 503


@auth_blueprint.route('/api/admin/account-users', methods=['POST'])
@top_admin_required
def add_account_user():
    if not _account_hub_enabled():
        return jsonify({'error': t('Account Hub is disabled.')}), 410
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'error': t('Account Hub user details must be an object.')}), 400
    if 'password' in data or 'role' in data:
        return jsonify({'error': t('Account Hub users are managed without local passwords or roles.')}), 400
    try:
        disabled = _boolean_field(data, 'disabled')
        pause = _boolean_field(data, 'pause_managed_subscriptions_when_disabled')
        user = ensure_account_hub_user(data.get('username'), data.get('email'))
        fields = {}
        if disabled is not None:
            fields['disabled'] = disabled
        if pause is not None:
            fields['pause_managed_subscriptions_when_disabled'] = pause
        if fields:
            user = update_account_hub_user(user['_id'], **fields)
        return jsonify({'data': _account_user_public(user)}), 201
    except (TypeError, ValueError) as exc:
        return _sub_admin_error(exc)
    except PyMongoError:
        return jsonify({'error': t('Unable to create Account Hub user.')}), 503


@auth_blueprint.route('/api/admin/account-users/<account_user_id>', methods=['PUT'])
@top_admin_required
def edit_account_user(account_user_id):
    if not _account_hub_enabled():
        return jsonify({'error': t('Account Hub is disabled.')}), 410
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'error': t('Account Hub user details must be an object.')}), 400
    if any(field in data for field in ('username', 'password', 'account_hub_uid')):
        return jsonify({'error': t('Account Hub identity fields cannot be changed.')}), 400
    fields = {}
    try:
        if 'email' in data:
            fields['email'] = validate_email(data.get('email'))
        if 'role' in data:
            fields['role'] = data['role']
        for name in ('disabled', 'pause_managed_subscriptions_when_disabled'):
            value = _boolean_field(data, name)
            if value is not None:
                fields[name] = value
        user = update_account_hub_user(account_user_id, **fields)
        return jsonify({'data': _account_user_public(user)})
    except LookupError as exc:
        return jsonify({'error': t(str(exc))}), 404
    except (TypeError, ValueError) as exc:
        return _sub_admin_error(exc)
    except PyMongoError:
        return jsonify({'error': t('Unable to update Account Hub user.')}), 503


@auth_blueprint.route('/api/admin/sub-admins', methods=['POST'])
@top_admin_required
def add_sub_admin():
    if _account_hub_enabled():
        return jsonify({'error': t('Account Hub user management has replaced sub-admin management.')}), 410
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'error': t('Sub-admin details must be an object.')}), 400
    try:
        disabled = _boolean_field(data, 'disabled')
        pause = _boolean_field(data, 'pause_managed_subscriptions_when_disabled')
        user = create_sub_admin(
            data.get('username'),
            data.get('password'),
            data.get('email'),
            disabled=False if disabled is None else disabled,
            pause_managed_subscriptions_when_disabled=False if pause is None else pause,
            parent_admin_id=current_user()['_id'],
        )
        return jsonify({'data': _sub_admin_public(user)}), 201
    except (TypeError, ValueError) as exc:
        return _sub_admin_error(exc)
    except PyMongoError:
        return jsonify({'error': t('Unable to create sub-admin.')}), 503


@auth_blueprint.route('/api/admin/sub-admins/<sub_admin_id>', methods=['PUT'])
@top_admin_required
def edit_sub_admin(sub_admin_id):
    if _account_hub_enabled():
        return jsonify({'error': t('Account Hub user management has replaced sub-admin management.')}), 410
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'error': t('Sub-admin details must be an object.')}), 400
    if 'username' in data:
        return jsonify({'error': t('Username cannot be changed.')}), 400
    fields = {}
    try:
        if 'email' in data:
            fields['email'] = validate_email(data.get('email'))
        if 'password' in data:
            fields['password'] = data.get('password')
        for name in ('disabled', 'pause_managed_subscriptions_when_disabled'):
            value = _boolean_field(data, name)
            if value is not None:
                fields[name] = value
        user = update_sub_admin(sub_admin_id, **fields)
        return jsonify({'data': _sub_admin_public(user)})
    except LookupError as exc:
        return jsonify({'error': t(str(exc))}), 404
    except (TypeError, ValueError) as exc:
        return _sub_admin_error(exc)
    except PyMongoError:
        return jsonify({'error': t('Unable to update sub-admin.')}), 503


@auth_blueprint.route('/api/admin/sub-admins/<sub_admin_id>', methods=['DELETE'])
@top_admin_required
def delete_sub_admin(sub_admin_id):
    if _account_hub_enabled():
        return jsonify({'error': t('Account Hub user management has replaced sub-admin management.')}), 410
    try:
        remove_sub_admin(sub_admin_id, current_user()['_id'])
        return jsonify({'success': True})
    except LookupError as exc:
        return jsonify({'error': t(str(exc))}), 404
    except PyMongoError:
        return jsonify({'error': t('Unable to remove sub-admin.')}), 503


@auth_blueprint.route('/api/auth/password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'error': t('Password change must be an object.')}), 400
    current_password = data.get('current_password') or ''
    new_password = data.get('new_password') or ''
    confirmation = data.get('new_password_confirmation') or ''

    if new_password != confirmation:
        return jsonify({'error': t('New passwords do not match.')}), 400
    if not new_password:
        return jsonify({'error': t('Password is required.')}), 400

    user = current_user()
    if user and user.get('auth_source') == AUTH_SOURCE_ACCOUNT_HUB:
        return jsonify({'error': t('Password changes are managed by Account Hub.')}), 403
    if user is None or not verify_password(user, current_password):
        return jsonify({'error': t('Current password is incorrect.')}), 400
    try:
        update_user_password(user, new_password)
    except ValueError as exc:
        return jsonify({'error': t(str(exc))}), 400
    except PyMongoError:
        return jsonify({'error': t('Unable to change password.')}), 503
    return jsonify({'success': True})

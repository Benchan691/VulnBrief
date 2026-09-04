from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for
from pymongo.errors import PyMongoError

from auth.store import (
    create_sub_admin,
    list_sub_admins,
    normalize_login,
    public_user,
    remove_sub_admin,
    update_sub_admin,
    update_user_password,
    validate_email,
    verify_login,
    verify_password,
)
from core.auth import current_user, login_required, top_admin_required
from core.i18n import t


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


@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_name = normalize_login(request.form.get('username'))
        password = request.form.get('password') or ''

        try:
            user = verify_login(login_name, password)
            if user is not None:
                session.clear()
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
    return render_template('auth/sub_admins.html')


@auth_blueprint.route('/api/admin/sub-admins')
@top_admin_required
def get_sub_admins():
    try:
        return jsonify({'data': [_sub_admin_public(user) for user in list_sub_admins()]})
    except PyMongoError:
        return jsonify({'error': t('Unable to load sub-admins.')}), 503


@auth_blueprint.route('/api/admin/sub-admins', methods=['POST'])
@top_admin_required
def add_sub_admin():
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
    if user is None or not verify_password(user, current_password):
        return jsonify({'error': t('Current password is incorrect.')}), 400
    try:
        update_user_password(user, new_password)
    except ValueError as exc:
        return jsonify({'error': t(str(exc))}), 400
    except PyMongoError:
        return jsonify({'error': t('Unable to change password.')}), 503
    return jsonify({'success': True})

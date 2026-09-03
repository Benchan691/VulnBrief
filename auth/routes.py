from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for
from pymongo.errors import PyMongoError

from auth.store import (
    normalize_login,
    update_user_password,
    verify_login,
    verify_password,
)
from core.auth import current_user, login_required
from core.i18n import t


auth_blueprint = Blueprint('auth', __name__)


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

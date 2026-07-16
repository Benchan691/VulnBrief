from flask import Blueprint, redirect, render_template, request, session, url_for
from pymongo.errors import PyMongoError

from auth.store import normalize_login, verify_login


auth_blueprint = Blueprint('auth', __name__)


@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_name = normalize_login(request.form.get('username'))
        password = request.form.get('password') or ''

        try:
            user = verify_login(login_name, password)
            if user is not None:
                session['username'] = user['username']
                return redirect(url_for('subscription.subscriptions'))
            return render_template('auth/login.html', error='Invalid username or password')
        except PyMongoError:
            return render_template(
                'auth/login.html',
                error='Unable to connect to the authentication database.',
            ), 503

    return render_template('auth/login.html')

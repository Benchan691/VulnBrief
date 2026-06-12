from . import auth_blueprint
from auth_store import normalize_login, verify_login
from flask import render_template, request, redirect, url_for, session
from pymongo.errors import PyMongoError


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
            return render_template('login.html', error='Invalid username or password')
        except PyMongoError:
            return render_template(
                'login.html',
                error='Unable to connect to the authentication database.',
            ), 503

    return render_template('login.html')

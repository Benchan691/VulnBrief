from functools import wraps

from flask import jsonify, redirect, request, session, url_for


def login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('auth.login'))
        return function(*args, **kwargs)

    return decorated_function

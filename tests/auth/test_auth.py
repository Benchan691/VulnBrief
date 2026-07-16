import bcrypt

import pytest

from app import app
from auth.store import ensure_bootstrap_user, upsert_user, verify_login
from core.database import get_web_database


@pytest.fixture(autouse=True)
def clear_auth():
    with app.app_context():
        get_web_database()['auth'].delete_many({})
    yield
    with app.app_context():
        get_web_database()['auth'].delete_many({})


def test_bootstrap_creates_default_user_when_auth_is_empty():
    with app.app_context():
        assert ensure_bootstrap_user(app.config) is True
        user = get_web_database()['auth'].find_one({'username': 'admin'})
        assert user is not None
        assert user['password'].startswith('$2')
        assert verify_login('admin', app.config['WEB_AUTH_BOOTSTRAP_PASSWORD']) is not None


def test_login_accepts_email_when_stored_on_user():
    with app.app_context():
        upsert_user('admin', 'secret-pass', email='ops@example.com')

    client = app.test_client()
    response = client.post('/login', data={
        'username': 'ops@example.com',
        'password': 'secret-pass',
    }, follow_redirects=False)

    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session['username'] == 'admin'


def test_login_rejects_wrong_password():
    with app.app_context():
        upsert_user('admin', 'secret-pass')

    client = app.test_client()
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'wrong',
    })

    assert response.status_code == 200
    assert b'Invalid username or password' in response.data


def test_login_rejects_plain_text_password_hash():
    with app.app_context():
        get_web_database()['auth'].insert_one({
            'username': 'legacy',
            'password': 'plain-text',
        })

    client = app.test_client()
    response = client.post('/login', data={
        'username': 'legacy',
        'password': 'plain-text',
    })

    assert response.status_code == 200
    assert b'Invalid username or password' in response.data

from app import app
from auth.store import ROLE_ADMIN, upsert_user


def authenticate(client, username='test-admin'):
    with app.app_context():
        upsert_user(username, 'test-password', role=ROLE_ADMIN)
    with client.session_transaction() as session:
        session['username'] = username

from datetime import datetime, timedelta, timezone

import pytest
from bson import ObjectId

from app import app
from auth.store import (
    ROLE_ADMIN,
    create_sub_admin,
    find_user,
    find_user_by_id,
    upsert_user,
    verify_login,
)
from core.database import get_web_database


PREFIX = 'scope-'


def _cleanup():
    with app.app_context():
        database = get_web_database()
        auth = database['auth']
        managed_ids = [item['_id'] for item in auth.find({
            'username': {'$regex': f'^{PREFIX}'},
        }, {'_id': 1})]
        for name in ('sub_account', 'report_jobs', 'newsletter_deliveries'):
            database[name].delete_many({
                '$or': [
                    {'managed_by_user_id': {'$in': managed_ids}},
                    {'username': {'$regex': f'^{PREFIX}'}},
                    {'email': {'$regex': f'^{PREFIX}'}},
                ],
            })
        auth.delete_many({'username': {'$regex': f'^{PREFIX}'}})


@pytest.fixture(autouse=True)
def clean_scope_records():
    _cleanup()
    yield
    _cleanup()


def _session_user(client, username, role=ROLE_ADMIN):
    with app.app_context():
        upsert_user(username, 'scope-password', role=role)
    with client.session_transaction() as session:
        session.clear()
        session['username'] = username
    with app.app_context():
        return find_user(username)


def _subscription(document_id, manager_id, username, email, *, newsletter=True):
    return {
        '_id': document_id,
        'owner_user_id': ObjectId(),
        'managed_by_user_id': manager_id,
        'username': username,
        'email': email,
        'emails': [email],
        'team': 'Scope test',
        'newsletter_profile': {
            'enabled': newsletter,
            'filters': {},
        },
        'report_profile': {
            'enabled': False,
            'filters': {},
        },
        'created_at': datetime.now(timezone.utc),
        'updated_at': datetime.now(timezone.utc),
    }


def test_top_admin_can_manage_sub_admin_lifecycle_and_disabled_sessions():
    client = app.test_client()
    root = _session_user(client, f'{PREFIX}root')
    dashboard = client.get('/')
    assert dashboard.status_code == 302
    assert dashboard.headers['Location'].endswith('/admin/sub-admins')
    assert b'Sub-admin Management' in client.get('/admin/sub-admins').data
    assert b'href="/subscriptions"' not in client.get('/admin/sub-admins').data
    assert b'href="/reviews"' not in client.get('/admin/sub-admins').data
    assert client.get('/admin/sub-admins').status_code == 200

    created = client.post('/api/admin/sub-admins', json={
        'username': f'{PREFIX}child',
        'password': 'child-password',
        'email': f'{PREFIX}child@example.com',
    })
    assert created.status_code == 201
    child = created.get_json()['data']
    assert child['role'] == 'sub_admin'
    assert 'password' not in child
    assert 'parent_admin_id' not in child

    duplicate_username = client.post('/api/admin/sub-admins', json={
        'username': f'{PREFIX}child',
        'password': 'another-password',
    })
    assert duplicate_username.status_code == 409

    duplicate_email = client.post('/api/admin/sub-admins', json={
        'username': f'{PREFIX}other',
        'password': 'another-password',
        'email': f'{PREFIX}child@example.com',
    })
    assert duplicate_email.status_code == 409

    invalid_password = client.post('/api/admin/sub-admins', json={
        'username': f'{PREFIX}invalid',
        'password': 'x' * 73,
    })
    assert invalid_password.status_code == 400

    child_client = app.test_client()
    with child_client.session_transaction() as session:
        session['username'] = f'{PREFIX}child'
    child_dashboard = child_client.get('/subscriptions')
    assert child_dashboard.status_code == 200
    assert b'href="/operations"' not in child_dashboard.data
    assert child_client.get('/admin/sub-admins').status_code == 403
    assert child_client.get('/api/admin/sub-admins').status_code == 403

    disabled = client.put(f"/api/admin/sub-admins/{child['id']}", json={
        'disabled': True,
        'pause_managed_subscriptions_when_disabled': True,
    })
    assert disabled.status_code == 200
    assert disabled.get_json()['data']['disabled'] is True
    assert verify_login(f'{PREFIX}child', 'child-password') is None
    assert child_client.get('/api/subscriptions').status_code == 401

    enabled = client.put(f"/api/admin/sub-admins/{child['id']}", json={
        'disabled': False,
        'password': 'reset-password',
    })
    assert enabled.status_code == 200
    assert verify_login(f'{PREFIX}child', 'reset-password') is not None

    immutable_username = client.put(f"/api/admin/sub-admins/{child['id']}", json={
        'username': f'{PREFIX}renamed',
    })
    assert immutable_username.status_code == 400

    root_delete = client.delete(f"/api/admin/sub-admins/{root['_id']}")
    assert root_delete.status_code == 404

    removed = client.delete(f"/api/admin/sub-admins/{child['id']}")
    assert removed.status_code == 200
    with app.app_context():
        assert find_user_by_id(child['id']) is None


def test_orphaned_subscriber_login_can_be_reclaimed_as_sub_admin():
    client = app.test_client()
    _session_user(client, f'{PREFIX}root')
    with app.app_context():
        orphan = upsert_user(
            f'{PREFIX}orphan',
            'orphan-password',
            email=f'{PREFIX}orphan@example.com',
        )
        orphan = find_user(f'{PREFIX}orphan')
        assert get_web_database()['sub_account'].count_documents({
            'owner_user_id': orphan['_id'],
        }) == 0

    created = client.post('/api/admin/sub-admins', json={
        'username': f'{PREFIX}orphan',
        'password': 'new-orphan-password',
        'email': f'{PREFIX}orphan@example.com',
    })
    assert created.status_code == 201
    assert created.get_json()['data']['role'] == 'sub_admin'
    with app.app_context():
        reclaimed = find_user(f'{PREFIX}orphan')
        assert reclaimed['_id'] == orphan['_id']
        assert verify_login(f'{PREFIX}orphan', 'new-orphan-password') is not None


def test_sub_admin_records_are_isolated_and_removal_reassigns_history():
    client = app.test_client()
    root = _session_user(client, f'{PREFIX}root')
    with app.app_context():
        first = create_sub_admin(
            f'{PREFIX}one', 'one-password', f'{PREFIX}one@example.com',
            parent_admin_id=root['_id'],
        )
        second = create_sub_admin(
            f'{PREFIX}two', 'two-password', f'{PREFIX}two@example.com',
            parent_admin_id=root['_id'],
        )
        first_subscription_id = ObjectId()
        second_subscription_id = ObjectId()
        first_job_id = ObjectId()
        second_job_id = ObjectId()
        database = get_web_database()
        database['sub_account'].insert_many([
            _subscription(first_subscription_id, first['_id'], f'{PREFIX}sub-one', f'{PREFIX}sub-one@example.com'),
            _subscription(second_subscription_id, second['_id'], f'{PREFIX}sub-two', f'{PREFIX}sub-two@example.com'),
        ])
        database['report_jobs'].insert_many([
            {'_id': first_job_id, 'status': 'completed', 'created_at': datetime.now(timezone.utc), 'managed_by_user_id': first['_id']},
            {'_id': second_job_id, 'status': 'completed', 'created_at': datetime.now(timezone.utc), 'managed_by_user_id': second['_id']},
        ])
        database['newsletter_deliveries'].insert_many([
            {'email': f'{PREFIX}sub-one@example.com', 'source_collection': 'avd', 'selection_id': 'scope-one', 'sent_at': datetime.now(timezone.utc), 'status': 'sent', 'managed_by_user_id': first['_id']},
            {'email': f'{PREFIX}sub-two@example.com', 'source_collection': 'avd', 'selection_id': 'scope-two', 'sent_at': datetime.now(timezone.utc), 'status': 'sent', 'managed_by_user_id': second['_id']},
        ])

    with client.session_transaction() as session:
        session.clear()
        session['username'] = f'{PREFIX}one'
    subscriptions = client.get('/api/subscriptions').get_json()['data']
    assert [item['id'] for item in subscriptions] == [str(first_subscription_id)]
    assert 'managed_by_user_id' not in subscriptions[0]

    cross_edit = client.put(f'/api/subscriptions/{second_subscription_id}', json={'team': 'No access'})
    assert cross_edit.status_code == 403
    assert client.delete(f'/api/subscriptions/{second_subscription_id}').status_code == 403
    cross_preview = client.post('/api/subscriptions/preview', json={
        'mode': 'update', 'subscription_id': str(second_subscription_id),
    })
    assert cross_preview.status_code == 403

    report_ids = [item['id'] for item in client.get('/api/reports').get_json()['data']]
    assert report_ids == [str(first_job_id)]
    assert client.get(f'/api/reports/{second_job_id}').status_code == 404
    assert client.delete(f'/api/reports/{second_job_id}').status_code == 404
    assert client.get(f'/reports/{second_job_id}/preview').status_code == 404

    health = client.get('/api/operations/health')
    assert health.status_code == 200
    assert {row['email'] for row in health.get_json()['newsletters']} == {f'{PREFIX}sub-one@example.com'}
    assert {row['selection_id'] for row in health.get_json()['recent_newsletter_deliveries']} == {'scope-one'}

    with client.session_transaction() as session:
        session.clear()
        session['username'] = f'{PREFIX}root'
    root_subscriptions = client.get('/api/subscriptions').get_json()['data']
    assert {item['id'] for item in root_subscriptions} == {
        str(first_subscription_id), str(second_subscription_id),
    }
    root_jobs = client.get('/api/reports').get_json()['data']
    assert {item['id'] for item in root_jobs} >= {str(first_job_id), str(second_job_id)}

    removed = client.delete(f'/api/admin/sub-admins/{first["_id"]}')
    assert removed.status_code == 200
    with app.app_context():
        database = get_web_database()
        assert database['sub_account'].find_one({'_id': first_subscription_id})['managed_by_user_id'] == root['_id']
        assert database['report_jobs'].find_one({'_id': first_job_id})['managed_by_user_id'] == root['_id']
        assert database['newsletter_deliveries'].find_one({'selection_id': 'scope-one'})['managed_by_user_id'] == root['_id']
        assert find_user_by_id(first['_id']) is None


def test_disabled_sub_admin_delivery_pause_is_applied_to_scheduled_work():
    from subscriptions.scheduler import due_monthly_statistic_subscriptions, due_scheduled_subscriptions
    from core.database import get_vulnerabilities_database

    client = app.test_client()
    root = _session_user(client, f'{PREFIX}root')
    now = datetime.now(timezone.utc)
    with app.app_context():
        paused = create_sub_admin(
            f'{PREFIX}paused', 'paused-password', f'{PREFIX}paused@example.com',
            disabled=True,
            pause_managed_subscriptions_when_disabled=True,
            parent_admin_id=root['_id'],
        )
        continuing = create_sub_admin(
            f'{PREFIX}continuing', 'continuing-password', f'{PREFIX}continuing@example.com',
            disabled=True,
            pause_managed_subscriptions_when_disabled=False,
            parent_admin_id=root['_id'],
        )
        database = get_web_database()
        documents = []
        for manager, username, email in (
            (paused, f'{PREFIX}paused-sub', f'{PREFIX}paused-sub@example.com'),
            (continuing, f'{PREFIX}continuing-sub', f'{PREFIX}continuing-sub@example.com'),
        ):
            documents.append({
                **_subscription(ObjectId(), manager['_id'], username, email),
                'report_profile': {
                    'enabled': True,
                    'schedule_enabled': True,
                    'schedule_weekday': 'mon',
                    'schedule_time': '09:00',
                    'next_run_at': now - timedelta(minutes=1),
                    'filters': {},
                },
                'newsletter_profile': {
                    'enabled': True,
                    'statistic_schedule_enabled': True,
                    'statistic_next_run_at': now - timedelta(minutes=1),
                    'filters': {},
                },
            })
        database['sub_account'].insert_many(documents)
        vuln_database = get_vulnerabilities_database()
        due_reports = due_scheduled_subscriptions(database, vuln_database, now=now)
        due_statistics = due_monthly_statistic_subscriptions(database, vuln_database, now=now)

    assert {item['managed_by_user_id'] for item in due_reports} == {continuing['_id']}
    assert {item['managed_by_user_id'] for item in due_statistics} == {continuing['_id']}


def test_newsletter_severity_filters_round_trip_through_subscription_api(monkeypatch):
    class FakeMailer:
        def __init__(self, config):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def send_email(self, receiver, email):
            pass

    monkeypatch.setattr('subscriptions.routes.Mailer', FakeMailer)
    client = app.test_client()
    _session_user(client, f'{PREFIX}root')
    page = client.get('/static/js/subscriptions/index.js')
    assert b'newsletter-status-' in page.data
    assert b'newsletter-include-unknown' in page.data
    email = f'{PREFIX}newsletter@example.com'
    created = client.post('/api/subscriptions', json={
        'username': f'{PREFIX}subscriber',
        'emails': [email],
        'team': 'Severity',
        'password': 'subscriber-password',
        'newsletter_profile': {
            'enabled': True,
            'filters': {
                'status': ['Critical', 'Low'],
                'include_unknown': True,
            },
        },
        'report_profile': {'enabled': False, 'filters': {}},
    })
    assert created.status_code == 201
    subscription_id = created.get_json()['id']
    stored = client.get('/api/subscriptions').get_json()['data'][0]
    assert stored['newsletter_profile']['filters']['status'] == ['Critical', 'Low']
    assert stored['newsletter_profile']['filters']['include_unknown'] is True

    updated = client.put(f'/api/subscriptions/{subscription_id}', json={
        'newsletter_profile': {
            'enabled': True,
            'filters': {'status': ['High'], 'include_unknown': False},
        },
        'report_profile': {'enabled': False, 'filters': {}},
    })
    assert updated.status_code == 200
    reloaded = client.get('/api/subscriptions').get_json()['data'][0]
    assert reloaded['newsletter_profile']['filters']['status'] == ['High']
    assert reloaded['newsletter_profile']['filters']['include_unknown'] is False

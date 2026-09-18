from datetime import datetime, timezone

import pytest

from scripts import cleanup_account_hub_migration as cleanup


class FakeDeleteResult:
    def __init__(self, deleted_count):
        self.deleted_count = deleted_count


class FakeCollection:
    def __init__(self, documents=None):
        self.documents = list(documents or [])

    def find(self, _query=None):
        return list(self.documents)

    def delete_many(self, query):
        ids = {_id for _id in query.get('_id', {}).get('$in', [])}
        before = len(self.documents)
        self.documents = [item for item in self.documents if item.get('_id') not in ids]
        return FakeDeleteResult(before - len(self.documents))


class FakeDatabase:
    def __init__(self, collections):
        self.collections = {
            name: FakeCollection(documents)
            for name, documents in collections.items()
        }

    def __getitem__(self, name):
        return self.collections.setdefault(name, FakeCollection())


def _auth(uid, username, *, source='account_hub', role='user', **extra):
    now = datetime.now(timezone.utc)
    return {
        '_id': uid,
        'username': username,
        'username_key': username.casefold(),
        'auth_source': source,
        'role': role,
        'disabled': False,
        'pause_managed_subscriptions_when_disabled': False,
        'must_change_password': False,
        'created_at': now,
        'updated_at': now,
        **extra,
    }


def _profile():
    return {'enabled': False, 'filters': {}}


def _subscription(uid, *, owner=2, manager=2):
    return {
        '_id': uid,
        'username': f'user-{uid}',
        'emails': [f'user-{uid}@example.com'],
        'email': f'user-{uid}@example.com',
        'team': 'Security',
        'delivery_mode': 'individual',
        'owner_user_id': owner,
        'managed_by_user_id': manager,
        'newsletter_profile': _profile(),
        'report_profile': _profile(),
    }


def _database():
    now = datetime.now(timezone.utc)
    return FakeDatabase({
        'auth': [
            _auth(1, 'local-admin', source='local', role='admin'),
            _auth(2, 'hub-user'),
            _auth(3, 'legacy-user', source='local'),
        ],
        'sub_account': [_subscription(20), _subscription(21, owner=3)],
        'report_jobs': [
            {'_id': 30, 'status': 'completed', 'input_source': 'review_selections',
             'created_at': now, 'updated_at': now, 'managed_by_user_id': 2},
            {'_id': 31, 'status': 'completed', 'input_source': 'review_selections',
             'created_at': now, 'updated_at': now, 'managed_by_user_id': 3},
        ],
        'report_job_inputs': [
            {'_id': 40, 'job_id': 30},
            {'_id': 41, 'job_id': 31},
        ],
        'report_job_results': [
            {'_id': 50, 'job_id': 30},
            {'_id': 51, 'job_id': 31},
        ],
        'newsletter_deliveries': [
            {'_id': 60, 'email': 'ok@example.com', 'database': 'vulnerabilities',
             'source_collection': 'cve', 'selection_id': 'CVE-1', 'sent_at': now,
             'managed_by_user_id': 2},
            {'_id': 61, 'email': 'old@example.com', 'database': 'vulnerabilities',
             'source_collection': 'cve', 'selection_id': 'CVE-2', 'sent_at': now,
             'managed_by_user_id': 3},
        ],
        'subscriptions': [{'_id': 70, 'email': 'legacy@example.com'}],
    })


@pytest.fixture(autouse=True)
def accept_profiles(monkeypatch):
    monkeypatch.setattr(cleanup, '_profile_error', lambda database, document: None)


def test_build_cleanup_plan_preserves_bootstrap_and_finds_orphans():
    database = _database()
    plan = cleanup.build_cleanup_plan(database, object(), 'local-admin')

    assert plan['preserved_auth_ids'] == {'1', '2'}
    assert plan['invalid_auth_ids'] == {'3'}
    assert {
        item['_id'] for item in plan['candidates']['auth']
    } == {3}
    assert {item['_id'] for item in plan['candidates']['sub_account']} == {21}
    assert {item['_id'] for item in plan['candidates']['report_jobs']} == {31}
    assert {item['_id'] for item in plan['candidates']['report_job_inputs']} == {41}
    assert {item['_id'] for item in plan['candidates']['report_job_results']} == {51}
    assert {item['_id'] for item in plan['candidates']['newsletter_deliveries']} == {61}
    assert {item['_id'] for item in plan['candidates']['subscriptions']} == {70}
    assert len(database['auth'].documents) == 3


def test_cleanup_refuses_to_delete_a_non_local_bootstrap_row():
    database = _database()
    database['auth'].documents[0]['auth_source'] = 'account_hub'
    with pytest.raises(ValueError, match='not backed by a local administrator'):
        cleanup.build_cleanup_plan(database, object(), 'local-admin')


def test_apply_cleanup_writes_backup_then_deletes_candidates(tmp_path):
    database = _database()
    plan = cleanup.build_cleanup_plan(database, object(), 'local-admin')
    backup_path, deleted = cleanup.apply_cleanup(database, plan, tmp_path / 'backup')

    assert backup_path.exists()
    assert backup_path.stat().st_mode & 0o777 == 0o600
    assert deleted['auth'] == 1
    assert deleted['sub_account'] == 1
    assert deleted['report_jobs'] == 1
    assert deleted['report_job_inputs'] == 1
    assert deleted['report_job_results'] == 1
    assert deleted['newsletter_deliveries'] == 1
    assert deleted['subscriptions'] == 1
    assert {item['_id'] for item in database['auth'].documents} == {1, 2}
    assert {item['_id'] for item in database['sub_account'].documents} == {20}
    assert {item['_id'] for item in database['report_jobs'].documents} == {30}
    assert {item['_id'] for item in database['report_job_inputs'].documents} == {40}
    assert {item['_id'] for item in database['report_job_results'].documents} == {50}
    assert {item['_id'] for item in database['newsletter_deliveries'].documents} == {60}
    assert database['subscriptions'].documents == []


def test_apply_cleanup_aborts_without_a_writable_backup(tmp_path):
    database = _database()
    plan = cleanup.build_cleanup_plan(database, object(), 'local-admin')
    backup_dir = tmp_path / 'already-exists'
    backup_dir.mkdir()
    with pytest.raises(FileExistsError):
        cleanup.apply_cleanup(database, plan, backup_dir)
    assert len(database['auth'].documents) == 3
    assert len(database['sub_account'].documents) == 2


def test_main_dry_run_never_mutates_database(monkeypatch, capsys):
    database = _database()
    monkeypatch.setattr(
        cleanup,
        'configure_application',
        lambda base_dir: {'WEB_AUTH_BOOTSTRAP_USERNAME': 'local-admin'},
    )
    monkeypatch.setattr(cleanup, 'get_web_database', lambda: database)
    monkeypatch.setattr(cleanup, 'get_vulnerabilities_database', lambda: object())

    assert cleanup.main(['--dry-run']) == 0
    output = capsys.readouterr().out
    assert 'Dry run only; no database changes were made.' in output
    assert len(database['auth'].documents) == 3
    assert len(database['subscriptions'].documents) == 1

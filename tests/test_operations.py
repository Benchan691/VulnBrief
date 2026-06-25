import copy
import time

from bson import ObjectId

import operations_runner
from app import app
from operations_runner import (
    build_command,
    default_config,
    load_config,
    reset_config,
    save_config,
    start_catch_up_schedule,
    start_operation,
    stop_catch_up_schedule,
    tick_scheduler,
)


def authenticate(client):
    with client.session_transaction() as session:
        session['username'] = 'test-user'


def test_operation_pages_require_authentication():
    client = app.test_client()

    assert client.get('/operations').status_code == 302
    assert client.get('/api/operations/config').status_code == 401
    assert client.post('/api/operations/schedule/catch_up/start').status_code == 401
    assert client.post('/api/operations/schedule/catch_up/stop').status_code == 401
    assert client.delete('/api/operations/config').status_code == 401


def test_operations_config_api(monkeypatch):
    database = FakeDatabase()
    monkeypatch.setattr('routes.operations.get_web_database', lambda: database)
    client = app.test_client()
    authenticate(client)

    response = client.put('/api/operations/config', json={
        'catch_up': {'interval_hours': 2, 'periodic_enabled': True},
    })

    assert response.status_code == 200
    body = response.get_json()
    assert body['avd_root'] == default_config()['avd_root']
    assert body['catch_up']['interval_hours'] == 2
    assert client.get('/api/operations/config').get_json()['catch_up']['periodic_enabled'] is True
    stored = database['operation_config'].documents['operations']
    assert 'avd_root' not in stored
    assert 'python_path' not in stored


def test_builds_configured_commands():
    config = default_config()
    config.update({
        'avd_root': '/repo',
        'python_path': '/repo/.venv/bin/python',
        'classifier_daemon_path': '/repo/vendor_product_classifier/classifier_daemon.py',
        'database': 'vulnerabilities',
    })
    config['review']['providers'] = 'cve, avd'
    config['reclassify_cve'] = {'limit': '50', 'zero_shot': True}

    assert build_command('review', config) == [
        '/repo/.venv/bin/python', '-m', 'vuln_scraper.cli', 'review', 'cve', 'avd'
    ]
    assert build_command('classifier_daemon', config) == [
        '/repo/.venv/bin/python', '/repo/vendor_product_classifier/classifier_daemon.py'
    ]
    assert build_command('reclassify_cve', config) == [
        '/repo/.venv/bin/python', '-m', 'vuln_scraper.cli', 'reclassify-cve',
        '--database', 'vulnerabilities', '--limit', '50', '--zero-shot'
    ]


def test_start_operation_records_output_and_blocks_duplicate(monkeypatch):
    database = FakeDatabase()
    config = save_config(database, {
        'avd_root': '/tmp',
        'python_path': 'python',
        'classifier_daemon_path': '/tmp/classifier_daemon.py',
    })
    monkeypatch.setattr(operations_runner, '_validate_command', lambda *_: None)

    run = start_operation(database, 'catch_up', popen=lambda *args, **kwargs: FakeProcess(['ok\n'], wait=0))
    wait_for(lambda: database['operation_runs'].documents[ObjectId(run['id'])]['status'] == 'succeeded')

    stored = database['operation_runs'].documents[ObjectId(run['id'])]
    assert stored['log'] == 'ok\n'
    assert stored['exit_code'] == 0


def test_start_operation_uses_avd_python_and_mongo_env(monkeypatch, tmp_path):
    avd_root = tmp_path / 'avd'
    python_path = avd_root / '.venv' / 'bin' / 'python'
    python_path.parent.mkdir(parents=True)
    python_path.touch()
    classifier = avd_root / 'classifier_daemon.py'
    classifier.touch()
    database = FakeDatabase()
    monkeypatch.setattr(operations_runner, 'default_config', lambda: {
        'avd_root': str(avd_root),
        'python_path': '/usr/local/bin/python3.11',
        'classifier_daemon_path': str(classifier),
        'database': 'vulnerabilities',
        'vuln_scrape_module': 'vuln_scraper.cli',
        'catch_up': default_config()['catch_up'],
        'review': {'providers': ''},
        'reclassify_cve': {'limit': '', 'zero_shot': False},
    })
    monkeypatch.setattr('mongo.get_config', lambda: {
        'MONGO_URI': 'mongodb://shared.example/',
        'VULNERABILITIES_DATABASE': 'vulnerabilities',
    })
    monkeypatch.setattr(operations_runner, '_validate_command', lambda *_: None)
    captured = {}

    def fake_popen(command, **kwargs):
        captured['command'] = command
        captured['env'] = kwargs['env']
        return FakeProcess(['ok\n'], wait=0)

    run = start_operation(database, 'catch_up', popen=fake_popen)
    wait_for(lambda: database['operation_runs'].documents[ObjectId(run['id'])]['status'] == 'succeeded')

    assert captured['command'][0] == str(python_path)
    assert captured['env']['MONGO_URI'] == 'mongodb://shared.example/'
    assert captured['env']['MONGO_DB'] == 'vulnerabilities'


def test_clear_operations_history_keeps_running(monkeypatch):
    database = FakeDatabase()
    runs = database['operation_runs']
    finished = ObjectId()
    running = ObjectId()
    runs.documents[finished] = {'_id': finished, 'status': 'failed'}
    runs.documents[running] = {'_id': running, 'status': 'running'}
    monkeypatch.setattr('routes.operations.get_web_database', lambda: database)
    client = app.test_client()
    authenticate(client)

    response = client.delete('/api/operations/runs')

    assert response.status_code == 200
    assert response.get_json()['deleted'] == 1
    assert finished not in runs.documents
    assert running in runs.documents


def test_tick_scheduler_starts_due_catch_up(monkeypatch):
    database = FakeDatabase()
    save_config(database, {
        'avd_root': '/tmp',
        'python_path': 'python',
        'classifier_daemon_path': '/tmp/classifier_daemon.py',
        'catch_up': {'periodic_enabled': True, 'interval_hours': 1, 'next_run_at': ''},
    })
    monkeypatch.setattr(operations_runner, '_validate_command', lambda *_: None)
    monkeypatch.setattr(operations_runner, 'subprocess', type('Subprocess', (), {
        'PIPE': object(),
        'STDOUT': object(),
        'Popen': lambda *args, **kwargs: FakeProcess([], wait=0),
    }))

    assert tick_scheduler(database) is True
    wait_for(lambda: len(database['operation_runs'].documents) == 1)
    assert database['operation_config'].documents['operations']['catch_up']['next_run_at']


def test_load_config_ignores_stored_path_overrides(monkeypatch, tmp_path):
    fallback_root = tmp_path / 'cyberclawer'
    fallback_root.mkdir()
    classifier = fallback_root / 'vendor_product_classifier' / 'classifier_daemon.py'
    classifier.parent.mkdir(parents=True)
    classifier.touch()
    monkeypatch.setattr(operations_runner, 'default_config', lambda: {
        'avd_root': str(fallback_root),
        'python_path': 'python',
        'classifier_daemon_path': str(classifier),
        'catch_up': default_config()['catch_up'],
        'review': {'providers': ''},
        'reclassify_cve': {'limit': '', 'zero_shot': False},
        'database': 'vulnerabilities',
        'vuln_scrape_module': 'vuln_scraper.cli',
    })
    database = FakeDatabase()
    database['operation_config'].documents['operations'] = {
        '_id': 'operations',
        'avd_root': '/stale/nonexistent/avd',
        'python_path': '/stale/nonexistent/avd/.venv/bin/python',
        'classifier_daemon_path': '/stale/nonexistent/avd/vendor_product_classifier/classifier_daemon.py',
        'catch_up': {'periodic_enabled': True},
    }

    loaded = load_config(database)

    assert loaded['avd_root'] == str(fallback_root)
    assert loaded['catch_up']['periodic_enabled'] is True


def test_reset_config_clears_persisted_settings(monkeypatch, tmp_path):
    database = FakeDatabase()
    save_config(database, {
        'catch_up': {'periodic_enabled': True, 'interval_hours': 6},
        'review': {'providers': 'cve'},
    })
    monkeypatch.setattr(operations_runner, 'default_config', lambda: {
        **default_config(),
        'catch_up': {**default_config()['catch_up'], 'periodic_enabled': False, 'interval_hours': 24},
    })

    reset = reset_config(database)

    assert 'operations' not in database['operation_config'].documents
    assert reset['catch_up']['periodic_enabled'] is False
    assert reset['catch_up']['interval_hours'] == 24


def test_start_and_stop_catch_up_schedule():
    database = FakeDatabase()
    save_config(database, {
        'avd_root': '/tmp',
        'python_path': 'python',
        'classifier_daemon_path': '/tmp/classifier_daemon.py',
        'catch_up': {'periodic_enabled': False, 'next_run_at': '2026-06-01T00:00:00+00:00'},
    })

    started = start_catch_up_schedule(database)
    assert started['catch_up']['periodic_enabled'] is True
    assert started['catch_up']['next_run_at'] == ''
    assert database['operation_config'].documents['operations']['catch_up']['periodic_enabled'] is True

    stopped = stop_catch_up_schedule(database)
    assert stopped['catch_up']['periodic_enabled'] is False
    assert database['operation_config'].documents['operations']['catch_up']['periodic_enabled'] is False


def test_catch_up_schedule_api(monkeypatch):
    database = FakeDatabase()
    save_config(database, {
        'avd_root': '/tmp',
        'python_path': 'python',
        'classifier_daemon_path': '/tmp/classifier_daemon.py',
        'catch_up': {'periodic_enabled': False},
    })
    monkeypatch.setattr('routes.operations.get_web_database', lambda: database)
    client = app.test_client()
    authenticate(client)

    start_response = client.post('/api/operations/schedule/catch_up/start')
    assert start_response.status_code == 200
    start_body = start_response.get_json()
    assert start_body['catch_up']['periodic_enabled'] is True
    assert start_body['catch_up']['next_run_at'] == ''

    stop_response = client.post('/api/operations/schedule/catch_up/stop')
    assert stop_response.status_code == 200
    stop_body = stop_response.get_json()
    assert stop_body['catch_up']['periodic_enabled'] is False


class FakeProcess:
    pid = 123

    def __init__(self, lines, wait=0):
        self.stdout = lines
        self._wait = wait
        self.terminated = False

    def wait(self):
        return self._wait

    def terminate(self):
        self.terminated = True


def wait_for(predicate):
    deadline = time.time() + 1
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate()


class InsertResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class DeleteResult:
    def __init__(self, deleted_count):
        self.deleted_count = deleted_count


class Cursor(list):
    def sort(self, field, direction):
        return Cursor(sorted(self, key=lambda item: item.get(field) or '', reverse=direction < 0))

    def limit(self, count):
        return Cursor(self[:count])


class ReplaceResult:
    def __init__(self, matched_count, upserted_id=None):
        self.matched_count = matched_count
        self.upserted_id = upserted_id


class FakeCollection:
    def __init__(self):
        self.documents = {}

    def find_one(self, query):
        for document in self.documents.values():
            if matches(document, query):
                return copy.deepcopy(document)
        return None

    def find(self, query):
        return Cursor(copy.deepcopy(document) for document in self.documents.values() if matches(document, query))

    def insert_one(self, document):
        inserted_id = ObjectId()
        stored = copy.deepcopy(document)
        stored['_id'] = inserted_id
        self.documents[inserted_id] = stored
        return InsertResult(inserted_id)

    def update_one(self, query, update, upsert=False):
        document = self.find_one(query)
        key = document['_id'] if document else query.get('_id')
        if key not in self.documents:
            self.documents[key] = {'_id': key}
        for field, value in update.get('$set', {}).items():
            set_path(self.documents[key], field, copy.deepcopy(value))

    def replace_one(self, query, document, upsert=False):
        existing = self.find_one(query)
        if existing:
            key = existing['_id']
            self.documents[key] = copy.deepcopy(document)
            return ReplaceResult(1)
        if not upsert:
            return ReplaceResult(0)
        key = document.get('_id', query.get('_id'))
        stored = copy.deepcopy(document)
        stored['_id'] = key
        self.documents[key] = stored
        return ReplaceResult(0, upserted_id=key)

    def delete_one(self, query):
        for key, document in list(self.documents.items()):
            if matches(document, query):
                del self.documents[key]
                return DeleteResult(1)
        return DeleteResult(0)

    def delete_many(self, query):
        keys = [key for key, document in self.documents.items() if matches(document, query)]
        for key in keys:
            del self.documents[key]
        return DeleteResult(len(keys))


class FakeDatabase:
    def __init__(self):
        self.collections = {}

    def __getitem__(self, name):
        self.collections.setdefault(name, FakeCollection())
        return self.collections[name]


def matches(document, query):
    for field, value in query.items():
        actual = value_at(document, field)
        if isinstance(value, dict) and '$ne' in value:
            if actual == value['$ne']:
                return False
        elif actual != value:
            return False
    return True


def value_at(document, field):
    value = document
    for part in field.split('.'):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def set_path(document, field, value):
    parts = field.split('.')
    for part in parts[:-1]:
        document = document.setdefault(part, {})
    document[parts[-1]] = value

import copy
import time

from bson import ObjectId

import operations_runner
from app import app
from operations_runner import build_command, default_config, save_config, start_operation, tick_scheduler


def authenticate(client):
    with client.session_transaction() as session:
        session['username'] = 'test-user'


def test_operation_pages_require_authentication():
    client = app.test_client()

    assert client.get('/operations').status_code == 302
    assert client.get('/api/operations/config').status_code == 401


def test_operations_config_api(monkeypatch):
    database = FakeDatabase()
    monkeypatch.setattr('routes.operations.get_web_database', lambda: database)
    client = app.test_client()
    authenticate(client)

    response = client.put('/api/operations/config', json={
        'avd_root': '/tmp/avd',
        'python_path': 'python',
        'classifier_daemon_path': '/tmp/avd/vendor_product_classifier/classifier_daemon.py',
        'catch_up': {'interval_hours': 2, 'periodic_enabled': True},
    })

    assert response.status_code == 200
    body = response.get_json()
    assert body['avd_root'] == '/tmp/avd'
    assert body['catch_up']['interval_hours'] == 2
    assert client.get('/api/operations/config').get_json()['catch_up']['periodic_enabled'] is True


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
    database = FakeDatabase()
    save_config(database, {
        'avd_root': str(avd_root),
        'python_path': '/usr/local/bin/python3.11',
        'classifier_daemon_path': str(avd_root / 'classifier_daemon.py'),
        'database': 'vulnerabilities',
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

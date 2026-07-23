import copy
import json
import re
from datetime import datetime, timedelta, timezone

from bson import ObjectId

from app import app
from operations.health import build_health_snapshot
from subscriptions.scheduler import (
    SCHEDULER_ALIVE_SECONDS,
    SCHEDULER_HEALTH_ID,
    read_scheduler_health,
    tick_email_scheduler,
    tick_retention,
)


def authenticate(client):
    with client.session_transaction() as session:
        session['username'] = 'test-user'


def _patch_review_views(monkeypatch):
    monkeypatch.setattr(
        'subscriptions.profiles.review_views',
        lambda database: {'cve_review': {'options': {'viewOn': 'cve', 'pipeline': []}}},
    )


def test_operations_page_requires_authentication():
    client = app.test_client()
    assert client.get('/operations').status_code == 302
    assert client.get('/api/operations/health').status_code == 401

    authenticate(client)
    page = client.get('/operations')
    assert page.status_code == 200
    assert b'/static/js/operations/index.js' in page.data
    match = re.search(
        rb'<script id="page-config" type="application/json">(.*?)</script>',
        page.data,
        re.DOTALL,
    )
    assert match
    page_config = json.loads(match.group(1))
    assert page_config['healthUrl'] == '/api/operations/health'


def test_operations_health_api(monkeypatch):
    now = datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc)
    job_id = ObjectId()
    account_id = ObjectId()
    delivery_id = ObjectId()
    web = FakeDatabase({
        'scheduler_health': {
            SCHEDULER_HEALTH_ID: {
                '_id': SCHEDULER_HEALTH_ID,
                'last_tick_at': now - timedelta(seconds=30),
                'hostname': 'web-1',
                'pid': 42,
                'retention': {
                    'last_run_at': now - timedelta(hours=1),
                    'last_result': {'web': 1, 'vulnerabilities': 2},
                },
            },
        },
        'sub_account': {
            account_id: {
                '_id': account_id,
                'email': 'ops@example.com',
                'team': 'SOC',
                'newsletter_profile': {
                    'enabled': True,
                    'filters': {'collections': ['cve_review']},
                    'delivery_cursor': '2026-07-01T00:00:00+00:00',
                    'cve_delivery_cutoff': '2026-06-01T00:00:00+00:00',
                },
                'report_profile': {
                    'enabled': True,
                    'filters': {'collections': ['cve_review']},
                    'generation_mode': 'template',
                    'report_language': 'en',
                    'schedule_enabled': True,
                    'schedule_weekday': 'mon',
                    'schedule_time': '09:00',
                    'next_run_at': now - timedelta(minutes=5),
                    'last_run_at': now - timedelta(days=7),
                    'last_job_id': str(job_id),
                    'last_error': '',
                    'last_match_count': 3,
                },
                'schedule_claim_owner': 'web-1',
                'schedule_claim_until': now + timedelta(minutes=10),
            },
        },
        'report_jobs': {
            job_id: {
                '_id': job_id,
                'status': 'completed',
                'delivery_status': 'completed',
                'delivery_error': '',
            },
        },
        'newsletter_deliveries': {
            delivery_id: {
                '_id': delivery_id,
                'email': 'ops@example.com',
                'source_collection': 'cve_review',
                'selection_id': 'CVE-2026-1',
                'title': 'Example CVE',
                'database': 'vulnerabilities',
                'sent_at': now - timedelta(hours=2),
            },
        },
    })
    monkeypatch.setattr('operations.routes.get_web_database', lambda: web)
    monkeypatch.setattr('operations.routes.get_vulnerabilities_database', lambda: FakeDatabase({}))
    monkeypatch.setattr(
        'operations.health.newsletter_delivery_statistics',
        lambda email, web_database=None: {
            'email': email,
            'total': 4,
            'by_collection': [{'database': 'vulnerabilities', 'source_collection': 'cve_review', 'count': 4}],
            'databases': ['vulnerabilities'],
        },
    )
    _patch_review_views(monkeypatch)

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return now if tz is None else now.astimezone(tz)

    monkeypatch.setattr('operations.health.datetime', FixedDateTime)

    client = app.test_client()
    authenticate(client)
    response = client.get('/api/operations/health')
    assert response.status_code == 200
    body = response.get_json()
    assert body['scheduler']['alive'] is True
    assert body['scheduler']['hostname'] == 'web-1'
    assert body['scheduler']['retention']['last_result']['web'] == 1
    assert body['reports'][0]['email'] == 'ops@example.com'
    assert body['reports'][0]['due'] is True
    assert body['reports'][0]['delivery']['delivery_status'] == 'completed'
    assert body['newsletters'][0]['total_delivered'] == 4
    assert body['newsletters'][0]['delivery_cursor'] == '2026-07-01T00:00:00+00:00'
    assert len(body['recent_newsletter_deliveries']) == 1


def test_read_scheduler_health_marks_stale_heartbeat():
    now = datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc)
    web = FakeDatabase({
        'scheduler_health': {
            SCHEDULER_HEALTH_ID: {
                '_id': SCHEDULER_HEALTH_ID,
                'last_tick_at': now - timedelta(seconds=SCHEDULER_ALIVE_SECONDS + 1),
                'hostname': 'web-1',
                'pid': 7,
            },
        },
    })
    health = read_scheduler_health(web, now=now)
    assert health['alive'] is False
    assert health['hostname'] == 'web-1'


def test_tick_email_scheduler_writes_heartbeat_and_skips_catch_up(monkeypatch):
    now = datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc)
    web = FakeDatabase({'scheduler_health': {}})
    calls = []

    monkeypatch.setattr(
        'subscriptions.scheduler.tick_scheduled_reports',
        lambda app, database, now=None: calls.append('reports') or 0,
    )
    monkeypatch.setattr(
        'subscriptions.scheduler.tick_newsletter_deliveries',
        lambda app, database, now=None: calls.append('newsletters') or 0,
    )
    monkeypatch.setattr(
        'subscriptions.scheduler.tick_retention',
        lambda database, now=None: calls.append('retention') or None,
    )

    did_work = tick_email_scheduler(object(), web, now=now)
    assert did_work is False
    assert calls == ['reports', 'newsletters', 'retention']
    stored = web['scheduler_health'].documents[SCHEDULER_HEALTH_ID]
    assert stored['last_tick_at'] == now
    assert 'catch_up' not in stored
    assert 'operation_runs' not in web.collections


def test_tick_retention_stores_state_on_scheduler_health(monkeypatch):
    now = datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc)
    web = FakeDatabase({'scheduler_health': {}})
    monkeypatch.setattr(
        'subscriptions.scheduler.purge_old_data',
        lambda web_database, vuln_database, now=None: {'web': 2, 'vulnerabilities': 1},
    )
    monkeypatch.setattr('subscriptions.scheduler.get_vulnerabilities_database', lambda: FakeDatabase({}))

    result = tick_retention(web, now=now)
    assert result == {'web': 2, 'vulnerabilities': 1}
    stored = web['scheduler_health'].documents[SCHEDULER_HEALTH_ID]
    assert stored['retention']['last_run_at'] == now
    assert stored['retention']['last_result'] == {'web': 2, 'vulnerabilities': 1}

    assert tick_retention(web, now=now + timedelta(hours=1)) is None


def test_build_health_snapshot_includes_due_report(monkeypatch):
    now = datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc)
    account_id = ObjectId()
    web = FakeDatabase({
        'scheduler_health': {
            SCHEDULER_HEALTH_ID: {
                '_id': SCHEDULER_HEALTH_ID,
                'last_tick_at': now,
                'hostname': 'local',
                'pid': 1,
            },
        },
        'sub_account': {
            account_id: {
                '_id': account_id,
                'email': 'a@example.com',
                'team': 'A',
                'newsletter_profile': {'enabled': False, 'filters': {}},
                'report_profile': {
                    'enabled': True,
                    'filters': {'collections': ['cve_review']},
                    'generation_mode': 'template',
                    'schedule_enabled': True,
                    'schedule_weekday': 'thu',
                    'schedule_time': '10:00',
                    'next_run_at': now - timedelta(seconds=1),
                },
            },
        },
        'newsletter_deliveries': {},
        'report_jobs': {},
    })
    _patch_review_views(monkeypatch)
    monkeypatch.setattr(
        'operations.health.newsletter_delivery_statistics',
        lambda email, web_database=None: {
            'email': email,
            'total': 0,
            'by_collection': [],
            'databases': [],
        },
    )

    snapshot = build_health_snapshot(web, FakeDatabase({}), now=now)
    assert snapshot['scheduler']['alive'] is True
    assert snapshot['reports'][0]['due'] is True
    assert snapshot['reports'][0]['schedule_weekday'] == 'thu'


class InsertResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class DeleteResult:
    def __init__(self, deleted_count):
        self.deleted_count = deleted_count


class Cursor(list):
    def sort(self, field, direction=-1):
        return Cursor(sorted(self, key=lambda item: item.get(field) or '', reverse=direction < 0))

    def limit(self, count):
        return Cursor(self[:count])


class FakeCollection:
    def __init__(self, documents=None):
        self.documents = {}
        source = documents or {}
        if isinstance(source, dict):
            items = source.values()
        else:
            items = source
        for document in items:
            stored = copy.deepcopy(document)
            key = stored.get('_id', ObjectId())
            stored['_id'] = key
            self.documents[key] = stored

    def find_one(self, query):
        for document in self.documents.values():
            if matches(document, query):
                return copy.deepcopy(document)
        return None

    def find(self, query=None):
        query = query or {}
        return Cursor(
            copy.deepcopy(document)
            for document in self.documents.values()
            if matches(document, query)
        )

    def insert_one(self, document):
        inserted_id = ObjectId()
        stored = copy.deepcopy(document)
        stored['_id'] = inserted_id
        self.documents[inserted_id] = stored
        return InsertResult(inserted_id)

    def update_one(self, query, update, upsert=False):
        document = self.find_one(query)
        if document is None:
            if not upsert:
                return
            key = query.get('_id', ObjectId())
            self.documents[key] = {'_id': key}
        else:
            key = document['_id']
        for field, value in update.get('$set', {}).items():
            set_path(self.documents[key], field, copy.deepcopy(value))

    def delete_many(self, query):
        keys = [key for key, document in self.documents.items() if matches(document, query)]
        for key in keys:
            del self.documents[key]
        return DeleteResult(len(keys))


class FakeDatabase:
    def __init__(self, collections=None):
        self.collections = {}
        for name, documents in (collections or {}).items():
            if isinstance(documents, FakeCollection):
                self.collections[name] = documents
            else:
                self.collections[name] = FakeCollection(documents)

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

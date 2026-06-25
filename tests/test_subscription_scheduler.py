from datetime import datetime, timezone

from bson import ObjectId

import subscription_scheduler
from app import app
from mongo import get_web_database
from subscription_scheduler import force_week_window, next_weekly_run, run_scheduled_report
from subscription_scheduler import purge_old_data


def test_next_weekly_run_uses_hong_kong_time():
    run_at = next_weekly_run(
        {'schedule_weekday': 'fri', 'schedule_time': '09:30'},
        datetime(2026, 6, 25, 1, 0, tzinfo=timezone.utc),
    )

    assert run_at.isoformat() == '2026-06-26T01:30:00+00:00'


def test_force_week_window_ignores_saved_window():
    profile = {'filters': {'time_window': 'all', 'start': 'x', 'end': 'y'}}

    forced = force_week_window(profile)

    assert forced['filters']['time_window'] == 'week'
    assert forced['filters']['start'] == ''
    assert forced['filters']['end'] == ''
    assert profile['filters']['time_window'] == 'all'


def test_run_scheduled_report_creates_job_and_sends_email(monkeypatch):
    sent = {}
    job_id = ObjectId()
    with app.app_context():
        web = get_web_database()
        subscription_id = ObjectId()
        web['sub_account'].delete_many({'_id': subscription_id})
        web['report_jobs'].delete_many({'_id': job_id})
        web['sub_account'].insert_one({
            '_id': subscription_id,
            'email': 'scheduled@example.com',
            'team': 'Scheduled',
            'report_profile': {
                'enabled': True,
                'generation_mode': 'enriched_weekly',
                'report_language': 'en',
                'schedule_enabled': True,
                'schedule_weekday': 'fri',
                'schedule_time': '09:30',
                'filters': {'time_window': 'all'},
            },
        })
        web['report_jobs'].insert_one({
            '_id': job_id,
            'status': 'completed',
            'generation_mode': 'enriched_weekly',
            'effective_generation_mode': 'enriched_weekly',
            'report_language': 'en',
            'effective_report_language': 'en',
            'source_count': 1,
            'report': {'title': 'Report'},
        })

        monkeypatch.setattr(subscription_scheduler, 'get_vulnerabilities_database', lambda: object())
        monkeypatch.setattr(subscription_scheduler, 'normalize_subscription', lambda database, raw: {
            **raw,
            'report_profile': raw['report_profile'],
        })
        monkeypatch.setattr(subscription_scheduler, 'query_profile_matches', lambda database, profile: [
            {'collection': 'cve_review', 'source_collection': 'cve', 'selection_id': 'cve:1'},
        ])
        monkeypatch.setattr(subscription_scheduler, 'create_job', lambda *args: str(job_id))
        monkeypatch.setattr(subscription_scheduler, 'run_job', lambda *args: None)
        monkeypatch.setattr(subscription_scheduler, '_render_job_html', lambda *args, **kwargs: '<h1>Report</h1>')
        monkeypatch.setattr(subscription_scheduler, 'send_html_email', lambda config, to, subject, html: sent.update({
            'to': to,
            'subject': subject,
            'html': html,
        }))

        run_scheduled_report(app, str(subscription_id))

        stored = web['sub_account'].find_one({'_id': subscription_id})
        assert stored['report_profile']['last_job_id'] == str(job_id)
        assert stored['report_profile']['last_match_count'] == 1
        assert stored['report_profile']['next_run_at']
        assert sent['to'] == 'scheduled@example.com'
        assert sent['html'] == '<h1>Report</h1>'

        web['sub_account'].delete_many({'_id': subscription_id})
        web['report_jobs'].delete_many({'_id': job_id})


def test_purge_old_data_removes_old_sources_and_report_artifacts(monkeypatch):
    old_job_id = ObjectId()
    running_job_id = ObjectId()
    web = FakeDatabase({
        'report_jobs': [
            {'_id': old_job_id, 'status': 'completed', 'created_at': datetime(2026, 5, 1, tzinfo=timezone.utc)},
            {'_id': running_job_id, 'status': 'running', 'created_at': datetime(2026, 5, 1, tzinfo=timezone.utc)},
        ],
        'report_job_inputs': [{'job_id': old_job_id}, {'job_id': running_job_id}],
        'report_job_results': [{'job_id': old_job_id}],
        'candidate_vulnerability_items': [{'run_id': str(old_job_id)}, {'run_id': str(running_job_id)}],
        'source_evidence_cache': [{'updated_at': '2026-05-01T00:00:00+00:00'}, {'updated_at': '2026-06-20T00:00:00+00:00'}],
        'search_enrichment_cache': [{'updated_at': '2026-05-01T00:00:00+00:00'}],
    })
    vuln = FakeDatabase({
        'cve': [
            {'_id': 'old', 'scraped_at': '2026-05-01T00:00:00+00:00'},
            {'_id': 'new', 'scraped_at': '2026-06-20T00:00:00+00:00'},
        ],
    })
    monkeypatch.setattr(subscription_scheduler, 'review_views', lambda database: {
        'cve_review': {'options': {'viewOn': 'cve'}},
    })

    deleted = purge_old_data(web, vuln, datetime(2026, 6, 25, tzinfo=timezone.utc))

    assert deleted['vulnerabilities'] == 1
    assert web['report_jobs'].documents == [{'_id': running_job_id, 'status': 'running', 'created_at': datetime(2026, 5, 1, tzinfo=timezone.utc)}]
    assert web['report_job_inputs'].documents == [{'job_id': running_job_id}]
    assert web['candidate_vulnerability_items'].documents == [{'run_id': str(running_job_id)}]
    assert web['source_evidence_cache'].documents == [{'updated_at': '2026-06-20T00:00:00+00:00'}]
    assert vuln['cve'].documents == [{'_id': 'new', 'scraped_at': '2026-06-20T00:00:00+00:00'}]


class FakeDeleteResult:
    def __init__(self, deleted_count):
        self.deleted_count = deleted_count


class FakeCollection:
    def __init__(self, documents=None):
        self.documents = list(documents or [])

    def find(self, query=None, projection=None):
        return [document for document in self.documents if _matches(document, query or {})]

    def delete_many(self, query):
        kept = [document for document in self.documents if not _matches(document, query)]
        deleted = len(self.documents) - len(kept)
        self.documents = kept
        return FakeDeleteResult(deleted)


class FakeDatabase:
    def __init__(self, collections):
        self.collections = {name: FakeCollection(documents) for name, documents in collections.items()}

    def __getitem__(self, name):
        self.collections.setdefault(name, FakeCollection())
        return self.collections[name]


def _matches(document, query):
    for field, expected in query.items():
        actual = document.get(field)
        if isinstance(expected, dict):
            if '$lt' in expected and not (actual < expected['$lt']):
                return False
            if '$in' in expected and actual not in expected['$in']:
                return False
            if '$nin' in expected and actual in expected['$nin']:
                return False
        elif actual != expected:
            return False
    return True

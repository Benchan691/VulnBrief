from datetime import datetime, timezone

from bson import ObjectId

import subscriptions.scheduler
from app import app
from core.database import get_web_database
from subscriptions.scheduler import next_weekly_run, run_scheduled_report
from subscriptions.scheduler import purge_old_data


def test_next_weekly_run_uses_hong_kong_time():
    run_at = next_weekly_run(
        {'schedule_weekday': 'fri', 'schedule_time': '09:30'},
        datetime(2026, 6, 25, 1, 0, tzinfo=timezone.utc),
    )

    assert run_at.isoformat() == '2026-06-26T01:30:00+00:00'


def test_run_scheduled_report_creates_job_and_sends_email(monkeypatch):
    sent = {}
    queried_profiles = []
    with app.app_context():
        web = get_web_database()
        subscription_id = ObjectId()
        web['sub_account'].delete_many({'_id': subscription_id})
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
                'filters': {'time_window': 'all', 'start': 'x', 'end': 'y'},
            },
        })

        monkeypatch.setattr(subscriptions.scheduler, 'get_vulnerabilities_database', lambda: object())
        monkeypatch.setattr(subscriptions.scheduler, 'normalize_subscription', lambda database, raw: {
            **raw,
            'report_profile': raw['report_profile'],
        })
        def fake_query_profile_matches(database, profile):
            queried_profiles.append(profile)
            return [{'collection': 'cve_review', 'source_collection': 'cve', 'selection_id': 'cve:1'}]
        monkeypatch.setattr(subscriptions.scheduler, 'query_profile_matches', fake_query_profile_matches)
        def fake_run_job(app_obj, job_id):
            web['report_jobs'].update_one(
                {'_id': ObjectId(job_id)},
                {'$set': {
                    'status': 'completed',
                    'generation_mode': 'enriched_weekly',
                    'effective_generation_mode': 'enriched_weekly',
                    'report_language': 'en',
                    'effective_report_language': 'en',
                    'source_count': 1,
                        'delivery_status': 'running',
                    'report': {'title': 'Report'},
                }},
            )
        monkeypatch.setattr(subscriptions.scheduler, 'run_job', fake_run_job)
        monkeypatch.setattr(subscriptions.scheduler, '_render_job_html', lambda *args, **kwargs: '<h1>Report</h1>')

        class FakeMailer:
            def __init__(self, config):
                self.config = config

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def send_email(self, receiver, email):
                sent.update({
                    'to': receiver,
                    'subject': email['subject'],
                    'html': email['html'],
                })

        monkeypatch.setattr(subscriptions.scheduler, 'Mailer', FakeMailer)

        run_scheduled_report(app, str(subscription_id))

        stored = web['sub_account'].find_one({'_id': subscription_id})
        assert stored['report_profile'].get('last_error', '') == ''
        assert stored['report_profile']['last_job_id']
        assert stored['report_profile']['last_match_count'] == 1
        assert stored['report_profile']['next_run_at']
        assert queried_profiles[0]['filters']['time_window'] == 'all'
        assert queried_profiles[0]['filters']['start'] == 'x'
        assert queried_profiles[0]['filters']['end'] == 'y'
        assert sent['to'] == 'scheduled@example.com'
        assert sent['html'] == '<h1>Report</h1>'

        web['sub_account'].delete_many({'_id': subscription_id})
        web['report_jobs'].delete_many({'_id': ObjectId(stored['report_profile']['last_job_id'])})


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
    monkeypatch.setattr(subscriptions.scheduler, 'review_views', lambda database: {
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


def test_deliver_pending_newsletters_initializes_cursor_without_sending(monkeypatch):
    from subscriptions.scheduler import deliver_pending_newsletters

    sent = []
    with app.app_context():
        web = get_web_database()
        subscription_id = ObjectId()
        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': 'newsletter@example.com'})
        web['sub_account'].insert_one({
            '_id': subscription_id,
            'email': 'newsletter@example.com',
            'team': 'News',
            'newsletter_profile': {
                'enabled': True,
                'filters': {'collections': ['avd_review']},
                'delivery_cursor': '',
            },
            'report_profile': {'enabled': False},
        })

        class FakeMailer:
            def __init__(self, config):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def send_email(self, receiver, email):
                sent.append((receiver, email))

        monkeypatch.setattr(subscriptions.scheduler, 'Mailer', FakeMailer)
        monkeypatch.setattr(
            subscriptions.scheduler,
            'query_profile_matches',
            lambda *args, **kwargs: [{
                'source_collection': 'avd',
                'selection_id': 'avd:old',
                'document': {
                    'scraped_at': '2026-01-01T00:00:00+00:00',
                    'title': 'Old',
                },
            }],
        )
        monkeypatch.setattr(
            subscriptions.scheduler,
            'resolve_vulnerability_document',
            lambda *args: document,
        )

        now = datetime(2026, 7, 16, 3, 0, tzinfo=timezone.utc)
        result = deliver_pending_newsletters(
            app,
            {
                '_id': subscription_id,
                'email': 'newsletter@example.com',
                'newsletter_profile': {
                    'enabled': True,
                    'filters': {'collections': ['avd_review']},
                    'delivery_cursor': '',
                },
            },
            now=now,
        )

        stored = web['sub_account'].find_one({'_id': subscription_id})
        assert result['sent'] == 0
        assert result['cursor_initialized'] is True
        assert stored['newsletter_profile']['delivery_cursor'] == now.isoformat()
        assert sent == []
        assert web['newsletter_deliveries'].count_documents({'email': 'newsletter@example.com'}) == 0

        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': 'newsletter@example.com'})


def test_deliver_pending_newsletters_sends_once_and_is_idempotent(monkeypatch):
    from subscriptions.scheduler import deliver_pending_newsletters

    sent = []
    with app.app_context():
        web = get_web_database()
        subscription_id = ObjectId()
        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': 'newsletter@example.com'})
        cursor = '2026-07-01T00:00:00+00:00'
        web['sub_account'].insert_one({
            '_id': subscription_id,
            'email': 'newsletter@example.com',
            'team': 'News',
            'newsletter_profile': {
                'enabled': True,
                'filters': {'collections': ['avd_review']},
                'delivery_cursor': cursor,
            },
            'report_profile': {'enabled': False},
        })

        newsletter_title = 'Ruijie AP180 series操作系统命令注入漏洞（CNVD-2026-2825856）'
        document = {
            'scraped_at': '2026-07-10T12:00:00+00:00',
            'title': newsletter_title,
            'description': 'Details',
        }

        class FakeMailer:
            def __init__(self, config):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def send_email(self, receiver, email):
                sent.append((receiver, email))

        monkeypatch.setattr(subscriptions.scheduler, 'Mailer', FakeMailer)
        monkeypatch.setattr(
            subscriptions.scheduler,
            'query_profile_matches',
            lambda *args, **kwargs: [{
                'source_collection': 'avd',
                'selection_id': 'avd:new',
                'document': document,
            }],
        )
        monkeypatch.setattr(
            subscriptions.scheduler,
            'resolve_vulnerability_document',
            lambda *args: document,
        )
        monkeypatch.setattr(
            subscriptions.scheduler,
            'render_newsletter',
                lambda document, source_collection: (
                '<p>newsletter</p>',
                {'title': newsletter_title},
            ),
        )

        first = deliver_pending_newsletters(
            app,
            {
                '_id': subscription_id,
                'email': 'newsletter@example.com',
                'newsletter_profile': {
                    'enabled': True,
                    'filters': {'collections': ['avd_review']},
                    'delivery_cursor': cursor,
                },
            },
            now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
        )
        second = deliver_pending_newsletters(
            app,
            {
                '_id': subscription_id,
                'email': 'newsletter@example.com',
                'newsletter_profile': {
                    'enabled': True,
                    'filters': {'collections': ['avd_review']},
                    'delivery_cursor': cursor,
                },
            },
            now=datetime(2026, 7, 16, 4, 1, tzinfo=timezone.utc),
        )

        stored = web['sub_account'].find_one({'_id': subscription_id})
        delivery = web['newsletter_deliveries'].find_one({
            'email': 'newsletter@example.com',
            'source_collection': 'avd',
            'selection_id': 'avd:new',
        })
        assert first['sent'] == 1
        assert second['sent'] == 0
        assert len(sent) == 1
        assert sent[0][0] == 'newsletter@example.com'
        assert sent[0][1]['subject'] == f'Security newsletter: {newsletter_title}'
        assert stored['newsletter_profile']['delivery_cursor'] == document['scraped_at']
        assert delivery is not None
        assert delivery['title'] == newsletter_title

        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': 'newsletter@example.com'})

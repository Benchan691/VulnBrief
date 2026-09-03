from datetime import datetime, timezone

from bson import ObjectId

import subscriptions.scheduler
from app import app
from core.database import get_web_database
from subscriptions.scheduler import (
    next_monthly_statistic_run,
    next_weekly_run,
    newsletter_delivery_statistics,
    previous_calendar_month_bounds,
    purge_old_data,
    run_monthly_statistic,
    run_scheduled_report,
)


def test_next_weekly_run_uses_hong_kong_time():
    run_at = next_weekly_run(
        {'schedule_weekday': 'fri', 'schedule_time': '09:30'},
        datetime(2026, 6, 25, 1, 0, tzinfo=timezone.utc),
    )

    assert run_at.isoformat() == '2026-06-26T01:30:00+00:00'


def test_previous_calendar_month_bounds_uses_hong_kong():
    start, end = previous_calendar_month_bounds(datetime(2026, 7, 15, 2, 0, tzinfo=timezone.utc))
    assert start.isoformat() == '2026-05-31T16:00:00+00:00'
    assert end.isoformat() == '2026-06-30T16:00:00+00:00'


def test_next_monthly_statistic_run_on_first_at_nine_hkt():
    # Before July 1 09:00 HKT → July 1 09:00 HKT
    before = next_monthly_statistic_run(datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc))
    assert before.isoformat() == '2026-07-01T01:00:00+00:00'
    # After July 1 09:00 HKT → August 1 09:00 HKT
    after = next_monthly_statistic_run(datetime(2026, 7, 1, 2, 0, tzinfo=timezone.utc))
    assert after.isoformat() == '2026-08-01T01:00:00+00:00'


def test_newsletter_delivery_statistics_filters_by_month():
    with app.app_context():
        get_web_database()['newsletter_deliveries'].delete_many({'email': 'month-stats@example.com'})
        get_web_database()['newsletter_deliveries'].insert_many([
            {
                'email': 'month-stats@example.com',
                'database': 'vulnerabilities',
                'source_collection': 'avd',
                'selection_id': 'avd:prev',
                'title': 'Prev',
                'sent_at': datetime(2026, 6, 15, 4, 0, tzinfo=timezone.utc),
            },
            {
                'email': 'month-stats@example.com',
                'database': 'vulnerabilities',
                'source_collection': 'avd',
                'selection_id': 'avd:curr',
                'title': 'Curr',
                'sent_at': datetime(2026, 7, 2, 4, 0, tzinfo=timezone.utc),
            },
        ])
        start, end = previous_calendar_month_bounds(datetime(2026, 7, 1, 2, 0, tzinfo=timezone.utc))
        stats = newsletter_delivery_statistics(
            'month-stats@example.com',
            get_web_database(),
            start=start,
            end=end,
        )
        assert stats['total'] == 1
        assert stats['period'] == 'June 2026'
        get_web_database()['newsletter_deliveries'].delete_many({'email': 'month-stats@example.com'})


def test_run_monthly_statistic_emails_previous_month_and_advances(monkeypatch):
    sent = {}
    with app.app_context():
        web = get_web_database()
        subscription_id = ObjectId()
        email = 'monthly-stat@example.com'
        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': email})
        web['sub_account'].insert_one({
            '_id': subscription_id,
            'email': email,
            'team': 'Monthly',
            'newsletter_profile': {
                'enabled': True,
                'statistic_schedule_enabled': True,
                'statistic_next_run_at': datetime(2026, 7, 1, 1, 0, tzinfo=timezone.utc),
                'filters': {},
            },
            'report_profile': {'enabled': False},
        })
        web['newsletter_deliveries'].insert_many([
            {
                'email': email,
                'database': 'vulnerabilities',
                'source_collection': 'avd',
                'selection_id': 'avd:june',
                'title': 'June',
                'sent_at': datetime(2026, 6, 10, 4, 0, tzinfo=timezone.utc),
            },
            {
                'email': email,
                'database': 'vulnerabilities',
                'source_collection': 'avd',
                'selection_id': 'avd:july',
                'title': 'July',
                'sent_at': datetime(2026, 7, 2, 4, 0, tzinfo=timezone.utc),
            },
        ])

        class FakeMailer:
            def __init__(self, config):
                self.config = config

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def send_email(self, receiver, email_payload):
                sent.update({
                    'to': receiver,
                    'subject': email_payload['subject'],
                    'html': email_payload['html'],
                })

        monkeypatch.setattr(subscriptions.scheduler, 'Mailer', FakeMailer)
        now = datetime(2026, 7, 1, 1, 5, tzinfo=timezone.utc)
        run_monthly_statistic(app, str(subscription_id), now=now)

        stored = web['sub_account'].find_one({'_id': subscription_id})
        assert stored['newsletter_profile'].get('statistic_last_error', '') == ''
        next_run = stored['newsletter_profile']['statistic_next_run_at']
        assert next_run.replace(tzinfo=timezone.utc).isoformat() == '2026-08-01T01:00:00+00:00'
        assert sent['to'] == email
        assert sent['subject'] == 'Newsletter delivery statistics — June 2026'
        assert 'Newsletters sent this period' in sent['html']
        assert 'metric-value' in sent['html']
        assert '1</p>' in sent['html'] or '>1<' in sent['html']
        assert 'avd' in sent['html'] or 'June' in sent['html']

        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': email})


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
            return [{
                'collection': 'cve_review',
                'source_collection': 'cve',
                'selection_id': 'cve:1',
                'vendor_product_match': {
                    'confidence': 'confirmed',
                    'matched_vendor': 'Acme',
                    'matched_product': 'Widget',
                    'row_number': 2,
                    'evidence': {'type': 'structured_pair'},
                },
            }]
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
        queued_input = web['report_job_inputs'].find_one({
            'job_id': ObjectId(stored['report_profile']['last_job_id']),
        })
        assert queued_input['vendor_product_match']['confidence'] == 'confirmed'

        web['sub_account'].delete_many({'_id': subscription_id})
        web['report_job_inputs'].delete_many({
            'job_id': ObjectId(stored['report_profile']['last_job_id']),
        })
        web['report_jobs'].delete_many({'_id': ObjectId(stored['report_profile']['last_job_id'])})


def test_run_scheduled_report_completes_without_email_when_inventory_has_no_matches(monkeypatch):
    with app.app_context():
        web = get_web_database()
        subscription_id = ObjectId()
        web['sub_account'].delete_many({'_id': subscription_id})
        web['sub_account'].insert_one({
            '_id': subscription_id,
            'email': 'no-matches@example.com',
            'team': 'No matches',
            'report_profile': {
                'enabled': True,
                'generation_mode': 'template',
                'report_language': 'en',
                'schedule_enabled': True,
                'schedule_weekday': 'fri',
                'schedule_time': '09:30',
                'filters': {},
            },
        })

        monkeypatch.setattr(subscriptions.scheduler, 'get_vulnerabilities_database', lambda: object())
        monkeypatch.setattr(
            subscriptions.scheduler,
            'normalize_subscription',
            lambda database, raw: {**raw, 'report_profile': raw['report_profile']},
        )
        monkeypatch.setattr(subscriptions.scheduler, 'query_profile_matches', lambda *args: [])
        monkeypatch.setattr(
            subscriptions.scheduler,
            'run_job',
            lambda *args, **kwargs: pytest.fail('report generation should not run'),
        )

        class UnexpectedMailer:
            def __init__(self, config):
                pytest.fail('email should not be sent')

        monkeypatch.setattr(subscriptions.scheduler, 'Mailer', UnexpectedMailer)

        run_scheduled_report(app, str(subscription_id))

        stored = web['sub_account'].find_one({'_id': subscription_id})
        job_id = ObjectId(stored['report_profile']['last_job_id'])
        job = web['report_jobs'].find_one({'_id': job_id})
        assert stored['report_profile']['last_error'] == ''
        assert stored['report_profile']['last_match_count'] == 0
        assert job['status'] == 'skipped'
        assert job['delivery_status'] == 'completed'
        assert job['source_count'] == 0
        assert job['status_message'] == 'No matching CVEs; no email was sent.'
        assert web['report_job_inputs'].count_documents({'job_id': job_id}) == 0

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
            {'_id': 'old', 'observed_at': datetime(2026, 5, 1, tzinfo=timezone.utc)},
            {'_id': 'new', 'observed_at': datetime(2026, 6, 20, tzinfo=timezone.utc)},
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
    assert vuln['cve'].documents == [{
        '_id': 'new',
        'observed_at': datetime(2026, 6, 20, tzinfo=timezone.utc),
    }]


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


def test_newsletter_delivery_cve_override_honors_collections_and_severity_filters():
    from subscriptions.scheduler import _newsletter_delivery_filter_overrides

    cutoff = '2026-07-23T04:00:00+00:00'
    default = _newsletter_delivery_filter_overrides({
        'filters': {'collections': [], 'status': [], 'severity_threshold': ''},
        'cve_delivery_cutoff': cutoff,
    })
    status_filtered = _newsletter_delivery_filter_overrides({
        'filters': {
            'collections': ['cve_review'],
            'status': ['High'],
            'severity_threshold': '',
            'include_unknown': False,
        },
        'cve_delivery_cutoff': cutoff,
    })
    threshold_filtered = _newsletter_delivery_filter_overrides({
        'filters': {
            'collections': ['cve_review'],
            'status': [],
            'severity_threshold': 'High',
            'include_unknown': False,
        },
        'cve_delivery_cutoff': cutoff,
    })

    assert default == {
        'cve_review': {
            'collections': [],
            'status': [],
            'severity_threshold': '',
            'include_unknown': True,
            'cve_delivery_cutoff': cutoff,
        },
    }
    assert status_filtered['cve_review']['status'] == ['High']
    assert status_filtered['cve_review']['include_unknown'] is False
    assert threshold_filtered['cve_review']['severity_threshold'] == 'High'
    assert threshold_filtered['cve_review']['include_unknown'] is False
    assert _newsletter_delivery_filter_overrides({
        'filters': {'collections': ['avd_review']},
        'cve_delivery_cutoff': cutoff,
    }) == {}


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
            'observed_at': datetime(2026, 7, 10, 12, tzinfo=timezone.utc),
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
        assert stored['newsletter_profile']['delivery_cursor'] == document['observed_at'].isoformat()
        assert delivery is not None
        assert delivery['title'] == newsletter_title

        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': 'newsletter@example.com'})


def test_deliver_pending_newsletters_skips_updated_cves(monkeypatch):
    from subscriptions.scheduler import deliver_pending_newsletters

    sent = []
    with app.app_context():
        web = get_web_database()
        subscription_id = ObjectId()
        cursor = '2026-07-01T00:00:00+00:00'
        document = {
            'observed_at': datetime(2026, 7, 10, 12, tzinfo=timezone.utc),
            'change_type': 'updated',
            'title': 'Updated CVE',
        }
        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': 'newsletter@example.com'})
        web['sub_account'].insert_one({
            '_id': subscription_id,
            'email': 'newsletter@example.com',
            'newsletter_profile': {
                'enabled': True,
                'filters': {'collections': ['cve_review']},
                'delivery_cursor': cursor,
            },
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
                'source_collection': 'cve',
                'selection_id': 'CVE-2026-1000',
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
            lambda *args: (_ for _ in ()).throw(AssertionError('updated CVEs must not be rendered')),
        )

        result = deliver_pending_newsletters(
            app,
            {
                '_id': subscription_id,
                'email': 'newsletter@example.com',
                'newsletter_profile': {
                    'enabled': True,
                    'filters': {'collections': ['cve_review']},
                    'delivery_cursor': cursor,
                },
            },
            now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
        )

        stored = web['sub_account'].find_one({'_id': subscription_id})
        assert result['sent'] == 0
        assert result['delivery_cursor'] == document['observed_at'].isoformat()
        assert sent == []
        assert stored['newsletter_profile']['delivery_cursor'] == document['observed_at'].isoformat()
        assert web['newsletter_deliveries'].count_documents({'email': 'newsletter@example.com'}) == 0

        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': 'newsletter@example.com'})


def test_deliver_pending_newsletters_fans_out_and_records_each_recipient(monkeypatch):
    from subscriptions.scheduler import deliver_pending_newsletters

    recipients = ['newsletter-a@example.com', 'newsletter-b@example.com']
    subscription_id = ObjectId()
    cursor = '2026-07-01T00:00:00+00:00'
    document = {
        'observed_at': datetime(2026, 7, 10, 12, tzinfo=timezone.utc),
        'title': 'Grouped test advisory',
    }
    sent = []
    with app.app_context():
        web = get_web_database()
        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': {'$in': recipients}})
        web['sub_account'].insert_one({
            '_id': subscription_id,
            'emails': recipients,
            'email': recipients[0],
            'delivery_mode': 'individual',
            'newsletter_profile': {
                'enabled': True,
                'filters': {'collections': ['avd_review']},
                'delivery_cursor': cursor,
            },
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
                'selection_id': 'avd:grouped',
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
                {'title': document['title']},
            ),
        )

        result = deliver_pending_newsletters(
            app,
            {
                '_id': subscription_id,
                'emails': recipients,
                'delivery_mode': 'individual',
                'newsletter_profile': {
                    'enabled': True,
                    'filters': {'collections': ['avd_review']},
                    'delivery_cursor': cursor,
                },
            },
            now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
        )

        assert result['sent'] == 2
        assert [receiver for receiver, _ in sent] == recipients
        assert web['newsletter_deliveries'].count_documents({
            'email': {'$in': recipients},
            'selection_id': 'avd:grouped',
        }) == 2
        assert web['sub_account'].find_one({'_id': subscription_id})['newsletter_profile']['delivery_cursor'] == document['observed_at'].isoformat()

        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': {'$in': recipients}})


def test_grouped_newsletter_delivery_uses_one_to_header(monkeypatch):
    from subscriptions.scheduler import deliver_pending_newsletters

    recipients = ['newsletter-grouped-a@example.com', 'newsletter-grouped-b@example.com']
    subscription_id = ObjectId()
    cursor = '2026-07-01T00:00:00+00:00'
    document = {
        'observed_at': datetime(2026, 7, 11, 12, tzinfo=timezone.utc),
        'title': 'Grouped delivery advisory',
    }
    sent = []
    with app.app_context():
        web = get_web_database()
        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': {'$in': recipients}})
        web['sub_account'].insert_one({
            '_id': subscription_id,
            'emails': recipients,
            'email': recipients[0],
            'delivery_mode': 'grouped',
            'newsletter_profile': {
                'enabled': True,
                'filters': {'collections': ['avd_review']},
                'delivery_cursor': cursor,
            },
        })

        class FakeMailer:
            def __init__(self, config):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def send_email(self, receiver, email):
                sent.append(receiver)

        monkeypatch.setattr(subscriptions.scheduler, 'Mailer', FakeMailer)
        monkeypatch.setattr(
            subscriptions.scheduler,
            'query_profile_matches',
            lambda *args, **kwargs: [{
                'source_collection': 'avd',
                'selection_id': 'avd:retry',
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
                {'title': document['title']},
            ),
        )

        subscription = {
            '_id': subscription_id,
            'emails': recipients,
            'delivery_mode': 'grouped',
            'newsletter_profile': {
                'enabled': True,
                'filters': {'collections': ['avd_review']},
                'delivery_cursor': cursor,
            },
        }
        first = deliver_pending_newsletters(
            app,
            subscription,
            now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
        )
        assert first['sent'] == 2
        assert first['delivery_cursor'] == document['observed_at'].isoformat()
        assert sent == ['newsletter-grouped-a@example.com, newsletter-grouped-b@example.com']
        assert web['newsletter_deliveries'].count_documents({
            'email': {'$in': recipients},
            'selection_id': 'avd:retry',
        }) == 2

        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': {'$in': recipients}})


def test_individual_newsletter_delivery_retries_only_failed_recipient(monkeypatch):
    from subscriptions.scheduler import deliver_pending_newsletters

    recipients = ['newsletter-retry-a@example.com', 'newsletter-retry-b@example.com']
    subscription_id = ObjectId()
    cursor = '2026-07-01T00:00:00+00:00'
    document = {
        'observed_at': datetime(2026, 7, 12, 12, tzinfo=timezone.utc),
        'title': 'Retry test advisory',
    }
    sent = []
    failed_once = {'value': True}
    with app.app_context():
        web = get_web_database()
        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': {'$in': recipients}})
        web['sub_account'].insert_one({
            '_id': subscription_id,
            'emails': recipients,
            'email': recipients[0],
            'delivery_mode': 'individual',
            'newsletter_profile': {
                'enabled': True,
                'filters': {'collections': ['avd_review']},
                'delivery_cursor': cursor,
            },
        })

        class FakeMailer:
            def __init__(self, config):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def send_email(self, receiver, email):
                sent.append(receiver)
                if receiver == recipients[1] and failed_once['value']:
                    failed_once['value'] = False
                    raise OSError('temporary delivery failure')

        monkeypatch.setattr(subscriptions.scheduler, 'Mailer', FakeMailer)
        monkeypatch.setattr(
            subscriptions.scheduler,
            'query_profile_matches',
            lambda *args, **kwargs: [{
                'source_collection': 'avd',
                'selection_id': 'avd:retry',
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
                {'title': document['title']},
            ),
        )

        subscription = {
            '_id': subscription_id,
            'emails': recipients,
            'delivery_mode': 'individual',
            'newsletter_profile': {
                'enabled': True,
                'filters': {'collections': ['avd_review']},
                'delivery_cursor': cursor,
            },
        }
        first = deliver_pending_newsletters(
            app,
            subscription,
            now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
        )
        assert first['sent'] == 1
        assert first['delivery_cursor'] == cursor
        assert sent == recipients
        assert web['newsletter_deliveries'].count_documents({
            'email': recipients[0],
            'selection_id': 'avd:retry',
        }) == 1
        assert web['newsletter_deliveries'].count_documents({
            'email': recipients[1],
            'selection_id': 'avd:retry',
            'status': 'failed',
        }) == 1
        assert newsletter_delivery_statistics(recipients, web)['total'] == 1

        second = deliver_pending_newsletters(
            app,
            subscription,
            now=datetime(2026, 7, 16, 4, 1, tzinfo=timezone.utc),
        )
        assert second['sent'] == 1
        assert second['delivery_cursor'] == document['observed_at'].isoformat()
        assert sent == [*recipients, recipients[1]]
        assert web['newsletter_deliveries'].count_documents({
            'email': {'$in': recipients},
            'selection_id': 'avd:retry',
        }) == 2
        assert newsletter_delivery_statistics(recipients, web)['total'] == 2

        web['sub_account'].delete_many({'_id': subscription_id})
        web['newsletter_deliveries'].delete_many({'email': {'$in': recipients}})

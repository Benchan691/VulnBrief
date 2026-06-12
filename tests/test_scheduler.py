from datetime import datetime, timedelta, timezone

from app import app
from mongo import get_web_database
from scheduler import run_due_report


TEST_EMAIL = 'scheduler-test@example.com'


def test_scheduler_claims_due_report_and_advances_schedule(monkeypatch):
    calls = []
    now = datetime.now(timezone.utc)
    with app.app_context():
        subscriptions = get_web_database()['subscriptions']
        subscriptions.delete_many({'email': TEST_EMAIL})
        subscriptions.insert_one({
            'email': TEST_EMAIL,
            'team': 'Test',
            'newsletter_profile': {'enabled': False, 'filters': {}},
            'report_profile': {
                'enabled': True,
                'filters': {},
                'generation_mode': 'template',
                'report_language': 'en',
                'schedule_enabled': True,
                'cron': '0 9 * * *',
                'next_run_at': now - timedelta(minutes=1),
            },
        })
        monkeypatch.setattr('scheduler.query_profile_matches', lambda database, profile: [{
            'collection': 'avd_review',
            'source_collection': 'avd',
            'selection_id': 'avd:test',
        }])
        monkeypatch.setattr('scheduler.create_job', lambda *args: 'job-id')
        monkeypatch.setattr('scheduler.run_job', lambda app, job_id: calls.append(job_id))
        try:
            assert run_due_report(app, 'owner') is True
            assert run_due_report(app, 'owner') is False
            stored = subscriptions.find_one({'email': TEST_EMAIL})
            assert calls == ['job-id']
            assert stored['report_profile']['last_job_id'] == 'job-id'
            assert stored['report_profile']['next_run_at'] > now.replace(tzinfo=None)
            assert 'schedule_claim_owner' not in stored
        finally:
            subscriptions.delete_many({'email': TEST_EMAIL})

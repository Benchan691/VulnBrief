import argparse
import time
import uuid
from datetime import datetime, timedelta, timezone

from pymongo import ReturnDocument

from app import create_app
from mongo import get_vulnerabilities_database, get_web_database
from report_harness import create_job, run_job
from subscription_data import next_cron_run, normalize_subscription, query_profile_matches


LEASE_SECONDS = 3600


def _subscriptions():
    return get_web_database()['subscriptions']


def initialize_schedules():
    database = get_vulnerabilities_database()
    for raw in _subscriptions().find({
        'report_profile.schedule_enabled': True,
        'report_profile.next_run_at': {'$exists': False},
    }):
        try:
            subscription = normalize_subscription(database, raw)
            next_run = next_cron_run(subscription['report_profile']['cron'])
            _subscriptions().update_one(
                {'_id': raw['_id']},
                {'$set': {'report_profile.next_run_at': next_run}},
            )
        except ValueError as exc:
            _subscriptions().update_one(
                {'_id': raw['_id']},
                {'$set': {'report_profile.last_error': str(exc)}},
            )


def run_due_report(app, owner):
    now = datetime.now(timezone.utc)
    raw = _subscriptions().find_one_and_update(
        {
            'report_profile.enabled': True,
            'report_profile.schedule_enabled': True,
            'report_profile.next_run_at': {'$lte': now},
            '$or': [
                {'schedule_claim_until': {'$lte': now}},
                {'schedule_claim_until': {'$exists': False}},
            ],
        },
        {'$set': {
            'schedule_claim_owner': owner,
            'schedule_claim_until': now + timedelta(seconds=LEASE_SECONDS),
        }},
        sort=[('report_profile.next_run_at', 1)],
        return_document=ReturnDocument.AFTER,
    )
    if raw is None:
        return False

    completed = {'report_profile.last_run_at': now}
    try:
        database = get_vulnerabilities_database()
        subscription = normalize_subscription(database, raw)
        profile = subscription['report_profile']
        completed['report_profile.next_run_at'] = next_cron_run(profile['cron'], now)
        _subscriptions().update_one(
            {'_id': raw['_id'], 'schedule_claim_owner': owner},
            {'$set': completed},
        )
        matches = query_profile_matches(database, profile)
        completed['report_profile.last_match_count'] = len(matches)
        if matches:
            job_id = create_job(
                matches,
                'review_selections',
                profile['generation_mode'],
                profile['report_language'],
            )
            completed['report_profile.last_job_id'] = job_id
            completed['report_profile.last_error'] = ''
            run_job(app, job_id)
        else:
            completed['report_profile.last_error'] = 'No records matched the scheduled report profile.'
    except Exception as exc:
        completed['report_profile.last_error'] = str(exc)
    finally:
        _subscriptions().update_one(
            {'_id': raw['_id'], 'schedule_claim_owner': owner},
            {
                '$set': completed,
                '$unset': {'schedule_claim_owner': '', 'schedule_claim_until': ''},
            },
        )
    return True


def run_once(app):
    owner = str(uuid.uuid4())
    with app.app_context():
        initialize_schedules()
        while run_due_report(app, owner):
            pass


def run_scheduler(app):
    interval = max(int(app.config['SCHEDULER_SCAN_INTERVAL_SECONDS']), 10)
    while True:
        try:
            run_once(app)
        except Exception as exc:
            print(f'Scheduler scan failed: {exc}', flush=True)
        time.sleep(interval)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run scheduled report generation.')
    parser.parse_args()
    run_scheduler(create_app())

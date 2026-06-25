import socket
import threading
from copy import deepcopy
from datetime import datetime, timedelta, timezone

from bson import ObjectId

from mailer import send_html_email
from mongo import get_vulnerabilities_database, get_web_database
from report_harness import _render_job_html, create_job, run_job
from review_data import review_views
from subscription_data import HONG_KONG, normalize_subscription, query_profile_matches


WEEKDAYS = {'mon': 0, 'tue': 1, 'wed': 2, 'thu': 3, 'fri': 4, 'sat': 5, 'sun': 6}
CLAIM_SECONDS = 60 * 60
RETENTION_DAYS = 30


def _now():
    return datetime.now(timezone.utc)


def _parse_time(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def next_weekly_run(profile, now=None):
    now_hkt = (now or _now()).astimezone(HONG_KONG)
    hour, minute = [int(part) for part in profile['schedule_time'].split(':')]
    target = now_hkt.replace(hour=hour, minute=minute, second=0, microsecond=0)
    days = (WEEKDAYS[profile['schedule_weekday']] - now_hkt.weekday()) % 7
    target += timedelta(days=days)
    if target <= now_hkt:
        target += timedelta(days=7)
    return target.astimezone(timezone.utc)


def due_scheduled_subscriptions(web_database, vuln_database, now=None):
    now = now or _now()
    expired_claim = {'$or': [
        {'schedule_claim_until': {'$exists': False}},
        {'schedule_claim_until': {'$lte': now}},
    ]}
    query = {
        'report_profile.enabled': True,
        'report_profile.schedule_enabled': True,
        '$and': [
            expired_claim,
            {'$or': [
                {'report_profile.next_run_at': {'$exists': False}},
                {'report_profile.next_run_at': ''},
                {'report_profile.next_run_at': {'$lte': now}},
            ]},
        ],
    }
    due = []
    for document in web_database['sub_account'].find(query):
        try:
            due.append(normalize_subscription(vuln_database, document))
        except ValueError:
            continue
    return due


def force_week_window(profile):
    profile = deepcopy(profile)
    profile['filters']['time_window'] = 'week'
    profile['filters']['start'] = ''
    profile['filters']['end'] = ''
    return profile


def _claim(collection, subscription, now):
    claim_until = now + timedelta(seconds=CLAIM_SECONDS)
    result = collection.update_one(
        {
            '_id': subscription['_id'],
            '$or': [
                {'schedule_claim_until': {'$exists': False}},
                {'schedule_claim_until': {'$lte': now}},
            ],
        },
        {'$set': {
            'schedule_claim_owner': socket.gethostname(),
            'schedule_claim_until': claim_until,
            'updated_at': now,
        }},
    )
    return getattr(result, 'modified_count', 1) != 0


def _translate_if_needed(report, generation_mode, language, config):
    if language == 'en':
        return report
    from enriched_report.translator import translate_report
    return translate_report(report, generation_mode, language, config)


def run_scheduled_report(app, subscription_id):
    with app.app_context():
        web_database = get_web_database()
        vuln_database = get_vulnerabilities_database()
        collection = web_database['sub_account']
        now = _now()
        raw = collection.find_one({'_id': ObjectId(subscription_id)})
        if raw is None:
            return
        try:
            subscription = normalize_subscription(vuln_database, raw)
            profile = force_week_window(subscription['report_profile'])
            matches = query_profile_matches(vuln_database, profile)
            update = {
                'report_profile.last_run_at': now,
                'report_profile.last_match_count': len(matches),
                'report_profile.next_run_at': next_weekly_run(profile, now),
                'report_profile.last_error': '',
                'schedule_claim_until': None,
                'schedule_claim_owner': '',
                'updated_at': now,
            }
            if not matches:
                collection.update_one({'_id': raw['_id']}, {'$set': update})
                return
            job_id = create_job(matches, 'review_selections', profile['generation_mode'], profile['report_language'])
            run_job(app, job_id)
            job = web_database['report_jobs'].find_one({'_id': ObjectId(job_id)})
            if not job or job.get('status') != 'completed':
                raise ValueError((job or {}).get('error') or 'Scheduled report job failed.')
            email_report = _translate_if_needed(
                job['report'],
                profile['generation_mode'],
                profile['report_language'],
                app.config,
            )
            html = _render_job_html(job, email_report, report_language=profile['report_language'])
            send_html_email(
                app.config,
                subscription['email'],
                f"Scheduled vulnerability report: {now.astimezone(HONG_KONG):%Y-%m-%d}",
                html,
            )
            update['report_profile.last_job_id'] = job_id
            collection.update_one({'_id': raw['_id']}, {'$set': update})
        except Exception as exc:
            failed_profile = {
                **{'schedule_weekday': 'mon', 'schedule_time': '09:00'},
                **(raw.get('report_profile') or {}),
            }
            collection.update_one({'_id': raw['_id']}, {'$set': {
                'report_profile.last_run_at': now,
                'report_profile.last_error': str(exc),
                'report_profile.next_run_at': next_weekly_run(failed_profile, now),
                'schedule_claim_until': None,
                'schedule_claim_owner': '',
                'updated_at': now,
            }})


def tick_scheduled_reports(app, web_database, now=None):
    now = now or _now()
    vuln_database = get_vulnerabilities_database()
    started = 0
    for subscription in due_scheduled_subscriptions(web_database, vuln_database, now):
        if not _claim(web_database['sub_account'], subscription, now):
            continue
        threading.Thread(
            target=run_scheduled_report,
            args=(app, str(subscription['_id'])),
            daemon=True,
        ).start()
        started += 1
    return started


def purge_old_data(web_database, vuln_database, now=None):
    cutoff = (now or _now()) - timedelta(days=RETENTION_DAYS)
    cutoff_iso = cutoff.isoformat()
    deleted = {'vulnerabilities': 0, 'web': 0}
    for collection_name in {view['options']['viewOn'] for view in review_views(vuln_database).values()}:
        deleted['vulnerabilities'] += vuln_database[collection_name].delete_many({'scraped_at': {'$lt': cutoff_iso}}).deleted_count
    old_jobs = list(web_database['report_jobs'].find({
        'status': {'$nin': ['queued', 'running']},
        'created_at': {'$lt': cutoff},
    }, {'_id': 1}))
    job_ids = [job['_id'] for job in old_jobs]
    run_ids = [str(job_id) for job_id in job_ids]
    if job_ids:
        deleted['web'] += web_database['report_job_inputs'].delete_many({'job_id': {'$in': job_ids}}).deleted_count
        deleted['web'] += web_database['report_job_results'].delete_many({'job_id': {'$in': job_ids}}).deleted_count
        deleted['web'] += web_database['report_jobs'].delete_many({'_id': {'$in': job_ids}}).deleted_count
    for name in (
        'candidate_vulnerability_items', 'search_enrichment_tasks', 'search_enrichment_results',
        'filtered_enrichment_results', 'source_evidence_cards', 'vulnerability_cards', 'report_metrics',
    ):
        deleted['web'] += web_database[name].delete_many({'run_id': {'$in': run_ids}}).deleted_count
    for name in ('source_evidence_cache', 'search_enrichment_cache'):
        deleted['web'] += web_database[name].delete_many({'updated_at': {'$lt': cutoff_iso}}).deleted_count
    return deleted


def tick_retention(web_database, now=None):
    now = now or _now()
    config = web_database['operation_config'].find_one({'_id': 'operations'}) or {}
    last_run = _parse_time((config.get('retention') or {}).get('last_run_at'))
    if last_run and now - last_run < timedelta(hours=24):
        return None
    result = purge_old_data(web_database, get_vulnerabilities_database(), now)
    web_database['operation_config'].update_one(
        {'_id': 'operations'},
        {'$set': {'retention.last_run_at': now, 'retention.last_result': result}},
        upsert=True,
    )
    return result

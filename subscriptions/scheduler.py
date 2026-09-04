import os
import inspect
import socket
import threading
import time
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from auth.store import managed_deliveries_paused
from core.database import get_config, get_vulnerabilities_database, get_web_database
from integrations.email import Mailer, send_to_recipients
from newsletters.normalizer import render_newsletter
from operations.templates import get_newsletter_template_config
from reports.progress import append_job_log
from reports.harness import _render_job_html, run_job
from reviews.repository import resolve_vulnerability_document
from subscriptions.profiles import HONG_KONG, normalize_subscription
from subscriptions.query import query_profile_matches
from subscriptions.sources import source_collection_for_review, subscription_review_views


# Keep this module-level name for existing integrations and test seams.
review_views = subscription_review_views


WEEKDAYS = {'mon': 0, 'tue': 1, 'wed': 2, 'thu': 3, 'fri': 4, 'sat': 5, 'sun': 6}
CLAIM_SECONDS = 60 * 60
RETENTION_DAYS = 30
NEWSLETTER_DELIVERIES = 'newsletter_deliveries'
NEWSLETTER_SEND_LIMIT = 20
SCHEDULER_HEALTH_COLLECTION = 'scheduler_health'
SCHEDULER_HEALTH_ID = 'email_scheduler'
SCHEDULER_CHECK_SECONDS = 60
SCHEDULER_ALIVE_SECONDS = 180
_newsletter_indexes_ready = False
_scheduler_started = False


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


STATISTIC_SCHEDULE_HOUR = 9
STATISTIC_SCHEDULE_MINUTE = 0


def previous_calendar_month_bounds(now=None):
    now_hkt = (now or _now()).astimezone(HONG_KONG)
    first_of_this_month = now_hkt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = first_of_this_month
    start = (first_of_this_month - timedelta(days=1)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def next_monthly_statistic_run(now=None):
    now_hkt = (now or _now()).astimezone(HONG_KONG)
    target = now_hkt.replace(
        day=1,
        hour=STATISTIC_SCHEDULE_HOUR,
        minute=STATISTIC_SCHEDULE_MINUTE,
        second=0,
        microsecond=0,
    )
    if target <= now_hkt:
        if now_hkt.month == 12:
            target = target.replace(year=now_hkt.year + 1, month=1)
        else:
            target = target.replace(month=now_hkt.month + 1)
    return target.astimezone(timezone.utc)


def calendar_month_label(start_utc):
    start_hkt = start_utc.astimezone(HONG_KONG)
    return start_hkt.strftime('%B %Y')


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
        if managed_deliveries_paused(document.get('managed_by_user_id')):
            continue
        try:
            due.append(normalize_subscription(vuln_database, document))
        except ValueError:
            continue
    return due


def due_monthly_statistic_subscriptions(web_database, vuln_database, now=None):
    now = now or _now()
    expired_claim = {'$or': [
        {'statistic_schedule_claim_until': {'$exists': False}},
        {'statistic_schedule_claim_until': {'$lte': now}},
    ]}
    query = {
        'newsletter_profile.enabled': True,
        'newsletter_profile.statistic_schedule_enabled': True,
        '$and': [
            expired_claim,
            {'$or': [
                {'newsletter_profile.statistic_next_run_at': {'$exists': False}},
                {'newsletter_profile.statistic_next_run_at': ''},
                {'newsletter_profile.statistic_next_run_at': {'$lte': now}},
            ]},
        ],
    }
    due = []
    for document in web_database['sub_account'].find(query):
        if managed_deliveries_paused(document.get('managed_by_user_id')):
            continue
        try:
            due.append(normalize_subscription(vuln_database, document))
        except ValueError:
            continue
    return due


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


def _claim_statistic_schedule(collection, subscription, now):
    claim_until = now + timedelta(seconds=CLAIM_SECONDS)
    result = collection.update_one(
        {
            '_id': subscription['_id'],
            '$or': [
                {'statistic_schedule_claim_until': {'$exists': False}},
                {'statistic_schedule_claim_until': {'$lte': now}},
            ],
        },
        {'$set': {
            'statistic_schedule_claim_owner': socket.gethostname(),
            'statistic_schedule_claim_until': claim_until,
            'updated_at': now,
        }},
    )
    return getattr(result, 'modified_count', 1) != 0


def _translate_if_needed(report, generation_mode, language, config):
    if language == 'en':
        return report
    from reports.enriched.translator import translate_report
    return translate_report(report, generation_mode, language, config)


def _placeholder_job(profile, now, managed_by_user_id=None):
    generation_mode = profile['generation_mode']
    if generation_mode == 'enriched_weekly':
        provider = 'Search API + llama-server'
        model = 'Enriched Weekly'
    else:
        provider = None
        model = 'Fixed Template'
    job = {
        'generation_mode': generation_mode,
        'effective_generation_mode': generation_mode,
        'report_language': 'en',
        'effective_report_language': 'en',
        'search_prompt': (profile.get('search_prompt') or '') if generation_mode == 'enriched_weekly' else '',
        'input_source': 'review_selections',
        'source_count': 0,
        'processed_count': 0,
        'current_position': 0,
        'item_fallback_count': 0,
        'status': 'queued',
        'created_at': now,
        'updated_at': now,
        'provider': provider,
        'model': model,
        'progress_percent': 0,
        'progress_current': 0,
        'progress_total': 1,
        'progress_label': 'Queued',
        'status_message': 'Queued for email delivery.',
        'estimated_seconds_remaining': None,
        'started_at': None,
        'pipeline_logs': [],
        'delivery_status': 'queued',
        'delivery_error': '',
    }
    if managed_by_user_id is not None:
        job['managed_by_user_id'] = managed_by_user_id
    return job


def _queue_subscription_job_inputs(job_id, matches, generation_mode):
    if not matches:
        raise ValueError('No records matched the report profile.')
    queued_inputs = []
    for position, item in enumerate(matches):
        if generation_mode == 'enriched_weekly' and (
            item.get('collection') != 'cve_review' or item.get('source_collection') != 'cve'
        ):
            raise ValueError('enriched_weekly reports only support cve_review selections.')
        queued_input = {
            'job_id': ObjectId(job_id),
            'position': position,
            'source_collection': item['source_collection'],
            'selection_id': item['selection_id'],
            'identifier': item['selection_id'],
        }
        if item.get('vendor_product_match'):
            queued_input['vendor_product_match'] = dict(item['vendor_product_match'])
        queued_inputs.append(queued_input)
    web_database = get_web_database()
    web_database['report_job_inputs'].delete_many({'job_id': ObjectId(job_id)})
    web_database['report_job_inputs'].insert_many(queued_inputs)
    web_database['report_jobs'].update_one(
        {'_id': ObjectId(job_id)},
        {'$set': {
            'source_count': len(matches),
            'progress_total': max(len(matches), 1),
            'updated_at': _now(),
        }},
    )


def start_subscription_report_job(subscription, profile):
    now = _now()
    job_id = get_web_database()['report_jobs'].insert_one(
        _placeholder_job(profile, now, subscription.get('managed_by_user_id'))
    ).inserted_id
    recipients = subscription.get('emails') or [subscription.get('email')]
    append_job_log(job_id, f'Queued subscription report email for {", ".join(recipients)}.')
    return {
        'job_id': str(job_id),
    }


def deliver_subscription_report_job(
    app,
    subscription,
    profile,
    job_id,
    *,
    match_count=None,
    now=None,
):
    now = now or _now()
    web_database = get_web_database()
    jobs = web_database['report_jobs']
    jobs.update_one(
        {'_id': ObjectId(job_id)},
        {'$set': {
            'delivery_status': 'running',
            'delivery_error': '',
            'status_message': 'Finding matching CVEs for email delivery.',
        }},
    )
    append_job_log(job_id, 'Starting subscription email delivery.')
    append_job_log(job_id, 'Finding matching CVEs.')
    matches = query_profile_matches(get_vulnerabilities_database(), profile)
    append_job_log(job_id, f'Found {len(matches)} matching CVE(s).')
    if not matches:
        completed_at = _now()
        append_job_log(job_id, 'No matching CVEs; completed without sending email.')
        jobs.update_one(
            {'_id': ObjectId(job_id)},
            {'$set': {
                'status': 'skipped',
                'delivery_status': 'completed',
                'delivery_error': '',
                'source_count': 0,
                'processed_count': 0,
                'progress_percent': 100,
                'progress_current': 1,
                'progress_total': 1,
                'progress_label': 'Skipped',
                'status_message': 'No matching CVEs; no email was sent.',
                'completed_at': completed_at,
                'updated_at': completed_at,
            }},
        )
        return {
            'job_id': job_id,
            'job': jobs.find_one({'_id': ObjectId(job_id)}),
            'match_count': 0,
        }
    append_job_log(job_id, 'Creating report job inputs.')
    _queue_subscription_job_inputs(job_id, matches, profile['generation_mode'])
    jobs.update_one(
        {'_id': ObjectId(job_id)},
        {'$set': {
            'status_message': 'Generating report for email delivery.',
            'updated_at': _now(),
        }},
    )
    run_job(app, job_id)
    job = web_database['report_jobs'].find_one({'_id': ObjectId(job_id)})
    if not job or job.get('status') != 'completed':
        jobs.update_one(
            {'_id': ObjectId(job_id)},
            {'$set': {
                'delivery_status': 'failed',
                'delivery_error': (job or {}).get('error') or 'Subscription report job failed.',
            }},
        )
        raise ValueError((job or {}).get('error') or 'Subscription report job failed.')
    append_job_log(job_id, 'Rendering HTML for subscription email.')
    email_report = _translate_if_needed(
        job['report'],
        profile['generation_mode'],
        profile['report_language'],
        app.config,
    )
    html = _render_job_html(job, email_report, report_language=profile['report_language'])
    recipients = subscription.get('emails') or [subscription.get('email')]
    delivery_mode = subscription.get('delivery_mode') or 'individual'
    append_job_log(job_id, f'Sending email to {", ".join(recipients)}.')
    with Mailer(app.config) as mailer:
        delivery = send_to_recipients(mailer, recipients, {
            'subject': f"Scheduled vulnerability report: {now.astimezone(HONG_KONG):%Y-%m-%d}",
            'html': html,
        }, delivery_mode)
    if delivery.get('failed'):
        failed = ', '.join(item[0] for item in delivery['failed'])
        error = f'Email delivery failed for: {failed}.'
        jobs.update_one(
            {'_id': ObjectId(job_id)},
            {'$set': {
                'delivery_status': 'failed',
                'delivery_error': error,
                'status_message': error,
            }},
        )
        append_job_log(job_id, error)
        raise RuntimeError(error)
    jobs.update_one(
        {'_id': ObjectId(job_id)},
        {'$set': {
            'delivery_status': 'completed',
            'delivery_error': '',
            'status_message': f'Email sent to {", ".join(recipients)}.',
        }},
    )
    append_job_log(job_id, f'Email sent to {", ".join(recipients)}.')
    return {
        'job_id': job_id,
        'job': job,
        'match_count': len(matches),
    }


def generate_and_send_subscription_report(
    app,
    subscription,
    profile,
    *,
    now=None,
):
    start = start_subscription_report_job(subscription, profile)
    return deliver_subscription_report_job(
        app,
        subscription,
        profile,
        start['job_id'],
        now=now,
    )


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
            if managed_deliveries_paused(subscription.get('managed_by_user_id')):
                collection.update_one({'_id': raw['_id']}, {'$set': {
                    'schedule_claim_until': None,
                    'schedule_claim_owner': '',
                    'updated_at': now,
                }})
                return
            profile = subscription['report_profile']
            update = {
                'report_profile.last_run_at': now,
                'report_profile.next_run_at': next_weekly_run(profile, now),
                'report_profile.last_error': '',
                'schedule_claim_until': None,
                'schedule_claim_owner': '',
                'updated_at': now,
            }
            result = generate_and_send_subscription_report(
                app,
                subscription,
                profile,
                now=now,
            )
            update['report_profile.last_match_count'] = result['match_count']
            update['report_profile.last_job_id'] = result['job_id']
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


def run_monthly_statistic(app, subscription_id, now=None):
    with app.app_context():
        web_database = get_web_database()
        vuln_database = get_vulnerabilities_database()
        collection = web_database['sub_account']
        now = now or _now()
        raw = collection.find_one({'_id': ObjectId(subscription_id)})
        if raw is None:
            return
        try:
            subscription = normalize_subscription(vuln_database, raw)
            if managed_deliveries_paused(subscription.get('managed_by_user_id')):
                collection.update_one({'_id': raw['_id']}, {'$set': {
                    'statistic_schedule_claim_until': None,
                    'statistic_schedule_claim_owner': '',
                    'updated_at': now,
                }})
                return
            recipients = subscription.get('emails') or [subscription.get('email')]
            start, end = previous_calendar_month_bounds(now)
            stats = newsletter_delivery_statistics(
                recipients,
                web_database,
                start=start,
                end=end,
                manager_user_id=subscription.get('managed_by_user_id'),
            )
            period = stats.get('period') or calendar_month_label(start)
            with Mailer(app.config) as mailer:
                delivery = send_to_recipients(mailer, recipients, {
                    'subject': f'Newsletter delivery statistics — {period}',
                    'html': render_newsletter_statistics_html(stats),
                }, subscription.get('delivery_mode') or 'individual')
            if delivery.get('failed'):
                failed = ', '.join(item[0] for item in delivery['failed'])
                raise RuntimeError(f'Email delivery failed for: {failed}.')
            collection.update_one({'_id': raw['_id']}, {'$set': {
                'newsletter_profile.statistic_last_run_at': now,
                'newsletter_profile.statistic_next_run_at': next_monthly_statistic_run(now),
                'newsletter_profile.statistic_last_error': '',
                'statistic_schedule_claim_until': None,
                'statistic_schedule_claim_owner': '',
                'updated_at': now,
            }})
        except Exception as exc:
            collection.update_one({'_id': raw['_id']}, {'$set': {
                'newsletter_profile.statistic_last_run_at': now,
                'newsletter_profile.statistic_last_error': str(exc),
                'newsletter_profile.statistic_next_run_at': next_monthly_statistic_run(now),
                'statistic_schedule_claim_until': None,
                'statistic_schedule_claim_owner': '',
                'updated_at': now,
            }})


def tick_monthly_statistics(app, web_database, now=None):
    now = now or _now()
    vuln_database = get_vulnerabilities_database()
    started = 0
    for subscription in due_monthly_statistic_subscriptions(web_database, vuln_database, now):
        if not _claim_statistic_schedule(web_database['sub_account'], subscription, now):
            continue
        threading.Thread(
            target=run_monthly_statistic,
            args=(app, str(subscription['_id']), now),
            daemon=True,
        ).start()
        started += 1
    return started


def purge_old_data(web_database, vuln_database, now=None):
    cutoff = (now or _now()) - timedelta(days=RETENTION_DAYS)
    cutoff_iso = cutoff.isoformat()
    deleted = {'vulnerabilities': 0, 'web': 0}
    for collection_name in {
        source_collection_for_review(name, view)
        for name, view in review_views(vuln_database).items()
    }:
        if not collection_name:
            continue
        deleted['vulnerabilities'] += vuln_database[collection_name].delete_many({'observed_at': {'$lt': cutoff}}).deleted_count
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


def _scheduler_health(web_database=None):
    if web_database is None:
        web_database = get_web_database()
    return web_database[SCHEDULER_HEALTH_COLLECTION]


def write_scheduler_heartbeat(web_database, now=None):
    now = now or _now()
    _scheduler_health(web_database).update_one(
        {'_id': SCHEDULER_HEALTH_ID},
        {'$set': {
            'last_tick_at': now,
            'hostname': socket.gethostname(),
            'pid': os.getpid(),
            'updated_at': now,
        }},
        upsert=True,
    )
    return now


def read_scheduler_health(web_database, now=None):
    now = now or _now()
    document = _scheduler_health(web_database).find_one({'_id': SCHEDULER_HEALTH_ID}) or {}
    last_tick_at = _parse_time(document.get('last_tick_at'))
    alive = bool(last_tick_at and (now - last_tick_at) <= timedelta(seconds=SCHEDULER_ALIVE_SECONDS))
    retention = document.get('retention') or {}
    return {
        'alive': alive,
        'last_tick_at': last_tick_at.isoformat() if last_tick_at else '',
        'hostname': document.get('hostname') or '',
        'pid': document.get('pid'),
        'retention': {
            'last_run_at': (
                _parse_time(retention.get('last_run_at')).isoformat()
                if _parse_time(retention.get('last_run_at'))
                else ''
            ),
            'last_result': retention.get('last_result'),
        },
    }


def tick_retention(web_database, now=None):
    now = now or _now()
    document = _scheduler_health(web_database).find_one({'_id': SCHEDULER_HEALTH_ID}) or {}
    last_run = _parse_time((document.get('retention') or {}).get('last_run_at'))
    if last_run and now - last_run < timedelta(hours=24):
        return None
    result = purge_old_data(web_database, get_vulnerabilities_database(), now)
    _scheduler_health(web_database).update_one(
        {'_id': SCHEDULER_HEALTH_ID},
        {'$set': {
            'retention.last_run_at': now,
            'retention.last_result': result,
            'updated_at': now,
        }},
        upsert=True,
    )
    return result


def tick_email_scheduler(app, web_database, now=None):
    now = now or _now()
    did_work = False
    try:
        did_work = bool(tick_scheduled_reports(app, web_database, now=now)) or did_work
    except Exception:
        pass
    try:
        did_work = bool(tick_monthly_statistics(app, web_database, now=now)) or did_work
    except Exception:
        pass
    try:
        did_work = bool(tick_newsletter_deliveries(app, web_database, now=now)) or did_work
    except Exception:
        pass
    try:
        did_work = tick_retention(web_database, now=now) is not None or did_work
    except Exception:
        pass
    write_scheduler_heartbeat(web_database, now=now)
    return did_work


def start_scheduler(app, database_factory):
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True

    def loop():
        while True:
            time.sleep(SCHEDULER_CHECK_SECONDS)
            with app.app_context():
                try:
                    tick_email_scheduler(app, database_factory())
                except Exception:
                    pass

    threading.Thread(target=loop, daemon=True).start()


def _newsletter_deliveries(web_database=None):
    if web_database is None:
        web_database = get_web_database()
    return web_database[NEWSLETTER_DELIVERIES]


def ensure_newsletter_delivery_indexes(web_database=None):
    global _newsletter_indexes_ready
    if _newsletter_indexes_ready:
        return
    _newsletter_deliveries(web_database).create_index(
        [('email', 1), ('source_collection', 1), ('selection_id', 1)],
        unique=True,
        name='newsletter_delivery_unique',
    )
    _newsletter_indexes_ready = True


def _vulnerabilities_database_name():
    return get_config()['VULNERABILITIES_DATABASE']


def _observed_at_value(document):
    value = (document or {}).get('observed_at')
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value or '')


def newsletter_delivery_statistics(
    email,
    web_database=None,
    start=None,
    end=None,
    *,
    manager_user_id=None,
):
    ensure_newsletter_delivery_indexes(web_database)
    collection = _newsletter_deliveries(web_database)
    emails = [email] if isinstance(email, str) else list(email or [])
    emails = [item for item in emails if isinstance(item, str) and item]
    match = {
        'email': {'$in': emails},
        '$or': [
            {'status': {'$exists': False}},
            {'status': 'sent'},
        ],
    }
    if start is not None or end is not None:
        sent_at = {}
        if start is not None:
            sent_at['$gte'] = start
        if end is not None:
            sent_at['$lt'] = end
        match['sent_at'] = sent_at
    if manager_user_id is not None:
        match['managed_by_user_id'] = manager_user_id
    pipeline = [
        {'$match': match},
        {'$group': {
            '_id': {
                'database': '$database',
                'source_collection': '$source_collection',
            },
            'count': {'$sum': 1},
        }},
        {'$sort': {'_id.database': 1, '_id.source_collection': 1}},
    ]
    by_collection = []
    databases = set()
    total = 0
    for row in collection.aggregate(pipeline):
        database_name = (row.get('_id') or {}).get('database') or _vulnerabilities_database_name()
        source_collection = (row.get('_id') or {}).get('source_collection') or ''
        count = int(row.get('count') or 0)
        databases.add(database_name)
        total += count
        by_collection.append({
            'database': database_name,
            'source_collection': source_collection,
            'count': count,
        })
    result = {
        'email': email if isinstance(email, str) else ', '.join(emails),
        'databases': sorted(databases) or [_vulnerabilities_database_name()],
        'by_collection': by_collection,
        'total': total,
    }
    if start is not None:
        result['period'] = calendar_month_label(start)
        result['period_start'] = start.isoformat()
        result['period_end'] = end.isoformat() if end is not None else ''
    return result


def render_newsletter_statistics_html(stats):
    from flask import render_template

    return render_template(
        'subscriptions/statistics_email.html',
        email=stats.get('email') or '',
        period=stats.get('period') or '',
        total=int(stats.get('total') or 0),
        databases=stats.get('databases') or [],
        by_collection=stats.get('by_collection') or [],
    )


def _already_delivered(web_database, email, source_collection, selection_id):
    delivery = _newsletter_deliveries(web_database).find_one({
        'email': email,
        'source_collection': source_collection,
        'selection_id': selection_id,
    })
    return delivery is not None and delivery.get('status', 'sent') == 'sent'


def _record_newsletter_delivery(
    web_database,
    *,
    email,
    database_name,
    source_collection,
    selection_id,
    title,
    sent_at,
    managed_by_user_id=None,
    status='sent',
    error='',
):
    document = {
        'email': email,
        'database': database_name,
        'source_collection': source_collection,
        'selection_id': selection_id,
        'title': title,
        'sent_at': sent_at,
        'status': status,
    }
    if managed_by_user_id is not None:
        document['managed_by_user_id'] = managed_by_user_id
    if error:
        document['error'] = error
    update = {'$set': document}
    if status == 'sent':
        update['$unset'] = {'error': ''}
    try:
        result = _newsletter_deliveries(web_database).update_one(
            {
                'email': email,
                'source_collection': source_collection,
                'selection_id': selection_id,
            },
            update,
            upsert=True,
        )
        return bool(result.upserted_id is not None or result.modified_count)
    except DuplicateKeyError:
        return False


def _is_updated_cve(source_collection, document):
    return (
        source_collection == 'cve'
        and str((document or {}).get('change_type') or '').strip().casefold() == 'updated'
    )


def _newsletter_delivery_filter_overrides(profile):
    """Apply CVE-only delivery safeguards without changing other sources."""
    filters = profile.get('filters') or {}
    collections = filters.get('collections') or []
    if collections and 'cve_review' not in collections:
        return {}

    cve_filters = dict(filters)
    if not cve_filters.get('status') and not cve_filters.get('severity_threshold'):
        # Newsletter subscriptions default to every new CVE, including CVEs
        # whose source record has no CVSS severity yet.
        cve_filters['include_unknown'] = True

    cutoff = str(profile.get('cve_delivery_cutoff') or '').strip()
    if cutoff:
        cve_filters['cve_delivery_cutoff'] = cutoff
    return {'cve_review': cve_filters}


def _render_configured_newsletter(document, source_collection, template_config):
    """Keep delivery-compatible with simple renderer fakes used by integrations/tests."""
    if len(inspect.signature(render_newsletter).parameters) >= 3:
        return render_newsletter(document, source_collection, template_config)
    return render_newsletter(document, source_collection)


def deliver_pending_newsletters(app, subscription, *, now=None, limit=NEWSLETTER_SEND_LIMIT):
    now = now or _now()
    web_database = get_web_database()
    ensure_newsletter_delivery_indexes(web_database)
    profile = subscription.get('newsletter_profile') or {}
    if not profile.get('enabled'):
        return {'sent': 0, 'cursor_initialized': False}
    if managed_deliveries_paused(subscription.get('managed_by_user_id')):
        return {'sent': 0, 'cursor_initialized': False, 'paused': True}

    cursor = str(profile.get('delivery_cursor') or '').strip()
    if not cursor:
        cursor_value = now.isoformat()
        web_database['sub_account'].update_one(
            {'_id': subscription['_id']},
            {'$set': {
                'newsletter_profile.delivery_cursor': cursor_value,
                'updated_at': now,
            }},
        )
        return {'sent': 0, 'cursor_initialized': True, 'delivery_cursor': cursor_value}

    vuln_database = get_vulnerabilities_database()
    recipients = subscription.get('emails') or [subscription.get('email')]
    recipients = [recipient for recipient in recipients if recipient]
    delivery_mode = subscription.get('delivery_mode') or 'individual'
    template_config = get_newsletter_template_config(web_database)
    database_name = _vulnerabilities_database_name()
    matches = query_profile_matches(
        vuln_database,
        {'filters': profile.get('filters') or {}},
        limit=None,
        include_documents=True,
        collection_filter_overrides=_newsletter_delivery_filter_overrides(profile),
    )
    pending = []
    for match in matches:
        document = match.get('document') or {}
        observed_at = _observed_at_value(document)
        if not observed_at or observed_at <= cursor:
            continue
        source_collection = match['source_collection']
        selection_id = match['selection_id']
        missing_recipients = [
            recipient for recipient in recipients
            if not _already_delivered(web_database, recipient, source_collection, selection_id)
        ]
        if observed_at <= cursor and not missing_recipients:
            continue
        pending.append((observed_at, match, document, missing_recipients))
    pending.sort(key=lambda item: item[0])

    sent = 0
    max_cursor = cursor
    cursor_blocked = False
    if not pending:
        return {'sent': 0, 'cursor_initialized': False, 'delivery_cursor': cursor}

    with Mailer(app.config) as mailer:
        for observed_at, match, document, missing_recipients in pending:
            if limit is not None and sent >= limit:
                break
            source_collection = match['source_collection']
            selection_id = match['selection_id']
            source_document = resolve_vulnerability_document(
                vuln_database, source_collection, selection_id,
            )
            if source_document is None:
                cursor_blocked = True
                continue
            if _is_updated_cve(source_collection, source_document):
                if not cursor_blocked and observed_at > max_cursor:
                    max_cursor = observed_at
                continue
            if not missing_recipients:
                if not cursor_blocked and observed_at > max_cursor:
                    max_cursor = observed_at
                continue
            html, newsletter = _render_configured_newsletter(
                source_document, source_collection, template_config,
            )
            title = newsletter.get('title') or selection_id
            delivery = send_to_recipients(mailer, missing_recipients, {
                'subject': newsletter.get('subject') or f'Security newsletter: {title}',
                'html': html,
            }, delivery_mode)
            for recipient in delivery.get('sent') or []:
                recorded = _record_newsletter_delivery(
                    web_database,
                    email=recipient,
                    database_name=database_name,
                    source_collection=source_collection,
                    selection_id=selection_id,
                    title=title,
                    sent_at=now,
                    managed_by_user_id=subscription.get('managed_by_user_id'),
                )
                if recorded:
                    sent += 1
            for recipient, error in delivery.get('failed') or []:
                _record_newsletter_delivery(
                    web_database,
                    email=recipient,
                    database_name=database_name,
                    source_collection=source_collection,
                    selection_id=selection_id,
                    title=title,
                    sent_at=now,
                    managed_by_user_id=subscription.get('managed_by_user_id'),
                    status='failed',
                    error=str(error),
                )
            if delivery.get('failed'):
                cursor_blocked = True
            elif not cursor_blocked and observed_at > max_cursor:
                max_cursor = observed_at
            if delivery.get('failed'):
                failed = ', '.join(item[0] for item in delivery['failed'])
                app.logger.error(
                    'Newsletter delivery failed for subscription %s: %s',
                    subscription.get('_id'),
                    failed,
                )

    if max_cursor != cursor:
        web_database['sub_account'].update_one(
            {'_id': subscription['_id']},
            {'$set': {
                'newsletter_profile.delivery_cursor': max_cursor,
                'updated_at': now,
            }},
        )
    return {'sent': sent, 'cursor_initialized': False, 'delivery_cursor': max_cursor}


def tick_newsletter_deliveries(app, web_database, now=None):
    now = now or _now()
    ensure_newsletter_delivery_indexes(web_database)
    vuln_database = get_vulnerabilities_database()
    sent_total = 0
    for document in web_database['sub_account'].find({'newsletter_profile.enabled': True}):
        try:
            subscription = normalize_subscription(vuln_database, document)
        except ValueError:
            continue
        subscription['_id'] = document['_id']
        if managed_deliveries_paused(subscription.get('managed_by_user_id')):
            continue
        try:
            result = deliver_pending_newsletters(app, subscription, now=now)
            sent_total += int(result.get('sent') or 0)
        except Exception:
            continue
    return sent_total

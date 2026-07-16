import socket
import threading
from datetime import datetime, timedelta, timezone
from html import escape

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from core.database import get_config, get_vulnerabilities_database, get_web_database
from integrations.email import Mailer
from newsletters.normalizer import render_newsletter
from reports.progress import append_job_log
from reports.harness import _render_job_html, run_job
from reviews.repository import review_views
from subscriptions.profiles import HONG_KONG, normalize_subscription
from subscriptions.query import query_profile_matches


WEEKDAYS = {'mon': 0, 'tue': 1, 'wed': 2, 'thu': 3, 'fri': 4, 'sat': 5, 'sun': 6}
CLAIM_SECONDS = 60 * 60
RETENTION_DAYS = 30
NEWSLETTER_DELIVERIES = 'newsletter_deliveries'
NEWSLETTER_SEND_LIMIT = 20
_newsletter_indexes_ready = False


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
    from reports.enriched.translator import translate_report
    return translate_report(report, generation_mode, language, config)


def _placeholder_job(profile, now):
    generation_mode = profile['generation_mode']
    if generation_mode == 'enriched_weekly':
        provider = 'Search API + llama-server'
        model = 'Enriched Weekly'
    else:
        provider = None
        model = 'Fixed Template'
    return {
        'generation_mode': generation_mode,
        'effective_generation_mode': generation_mode,
        'report_language': 'en',
        'effective_report_language': 'en',
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


def _queue_subscription_job_inputs(job_id, matches, generation_mode):
    if not matches:
        raise ValueError('No records matched the report profile.')
    queued_inputs = []
    for position, item in enumerate(matches):
        if generation_mode == 'enriched_weekly' and (
            item.get('collection') != 'cve_review' or item.get('source_collection') != 'cve'
        ):
            raise ValueError('enriched_weekly reports only support cve_review selections.')
        queued_inputs.append({
            'job_id': ObjectId(job_id),
            'position': position,
            'source_collection': item['source_collection'],
            'selection_id': item['selection_id'],
            'identifier': item['selection_id'],
        })
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
    job_id = get_web_database()['report_jobs'].insert_one(_placeholder_job(profile, now)).inserted_id
    append_job_log(job_id, f'Queued subscription report email for {subscription["email"]}.')
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
    append_job_log(job_id, f'Sending email to {subscription["email"]}.')
    with Mailer(app.config) as mailer:
        mailer.send_email(subscription['email'], {
            'subject': f"Scheduled vulnerability report: {now.astimezone(HONG_KONG):%Y-%m-%d}",
            'html': html,
        })
    jobs.update_one(
        {'_id': ObjectId(job_id)},
        {'$set': {
            'delivery_status': 'completed',
            'delivery_error': '',
            'status_message': f'Email sent to {subscription["email"]}.',
        }},
    )
    append_job_log(job_id, f'Email sent to {subscription["email"]}.')
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


def _scraped_at_value(document):
    return str((document or {}).get('scraped_at') or '')


def newsletter_delivery_statistics(email, web_database=None):
    ensure_newsletter_delivery_indexes(web_database)
    collection = _newsletter_deliveries(web_database)
    pipeline = [
        {'$match': {'email': email}},
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
    return {
        'email': email,
        'databases': sorted(databases) or [_vulnerabilities_database_name()],
        'by_collection': by_collection,
        'total': total,
    }


def render_newsletter_statistics_html(stats):
    rows = ''.join(
        (
            '<tr>'
            f'<td>{escape(item["database"])}</td>'
            f'<td>{escape(item["source_collection"])}</td>'
            f'<td>{item["count"]}</td>'
            '</tr>'
        )
        for item in stats.get('by_collection') or []
    )
    if not rows:
        rows = '<tr><td colspan="3">No newsletters have been sent yet.</td></tr>'
    databases = ', '.join(escape(name) for name in (stats.get('databases') or []))
    return (
        '<h2>Newsletter delivery statistics</h2>'
        f'<p>Recipient: <strong>{escape(stats.get("email") or "")}</strong></p>'
        f'<p>Database(s): <strong>{databases}</strong></p>'
        f'<p>Total newsletters sent: <strong>{int(stats.get("total") or 0)}</strong></p>'
        '<table border="1" cellpadding="6" cellspacing="0">'
        '<thead><tr><th>Database</th><th>Collection</th><th>Sent</th></tr></thead>'
        f'<tbody>{rows}</tbody>'
        '</table>'
    )


def _already_delivered(web_database, email, source_collection, selection_id):
    return _newsletter_deliveries(web_database).find_one({
        'email': email,
        'source_collection': source_collection,
        'selection_id': selection_id,
    }) is not None


def _record_newsletter_delivery(web_database, *, email, database_name, source_collection, selection_id, title, sent_at):
    try:
        _newsletter_deliveries(web_database).insert_one({
            'email': email,
            'database': database_name,
            'source_collection': source_collection,
            'selection_id': selection_id,
            'title': title,
            'sent_at': sent_at,
        })
        return True
    except DuplicateKeyError:
        return False


def deliver_pending_newsletters(app, subscription, *, now=None, limit=NEWSLETTER_SEND_LIMIT):
    now = now or _now()
    web_database = get_web_database()
    ensure_newsletter_delivery_indexes(web_database)
    profile = subscription.get('newsletter_profile') or {}
    if not profile.get('enabled'):
        return {'sent': 0, 'cursor_initialized': False}

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
    database_name = _vulnerabilities_database_name()
    matches = query_profile_matches(
        vuln_database,
        {'filters': profile.get('filters') or {}},
        limit=None,
        include_documents=True,
    )
    pending = []
    for match in matches:
        document = match.get('document') or {}
        scraped_at = _scraped_at_value(document)
        if not scraped_at or scraped_at <= cursor:
            continue
        source_collection = match['source_collection']
        selection_id = match['selection_id']
        if _already_delivered(web_database, subscription['email'], source_collection, selection_id):
            continue
        pending.append((scraped_at, match, document))
    pending.sort(key=lambda item: item[0])
    if limit is not None:
        pending = pending[:limit]

    sent = 0
    max_cursor = cursor
    if not pending:
        return {'sent': 0, 'cursor_initialized': False, 'delivery_cursor': cursor}

    with Mailer(app.config) as mailer:
        for scraped_at, match, document in pending:
            source_collection = match['source_collection']
            selection_id = match['selection_id']
            html, newsletter = render_newsletter(document, source_collection)
            title = newsletter.get('title') or selection_id
            mailer.send_email(subscription['email'], {
                'subject': f'Security newsletter: {title}',
                'html': html,
            })
            recorded = _record_newsletter_delivery(
                web_database,
                email=subscription['email'],
                database_name=database_name,
                source_collection=source_collection,
                selection_id=selection_id,
                title=title,
                sent_at=now,
            )
            if not recorded:
                continue
            sent += 1
            if scraped_at > max_cursor:
                max_cursor = scraped_at

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
        try:
            result = deliver_pending_newsletters(app, subscription, now=now)
            sent_total += int(result.get('sent') or 0)
        except Exception:
            continue
    return sent_total

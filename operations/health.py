from datetime import datetime, timezone

from bson import ObjectId

from subscriptions.profiles import normalize_subscription
from subscriptions.scheduler import (
    NEWSLETTER_DELIVERIES,
    _parse_time,
    newsletter_delivery_statistics,
    read_scheduler_health,
)


RECENT_NEWSLETTER_LIMIT = 20


def _iso(value):
    parsed = _parse_time(value)
    if parsed is not None:
        return parsed.isoformat()
    if value is None:
        return ''
    return str(value)


def _job_delivery(web_database, job_id, manager_user_id=None):
    if not job_id:
        return None
    try:
        query = {'_id': ObjectId(str(job_id))}
        if manager_user_id is not None:
            query['managed_by_user_id'] = manager_user_id
        job = web_database['report_jobs'].find_one(query)
    except Exception:
        job = None
    if job is None:
        return {
            'job_id': str(job_id),
            'status': '',
            'delivery_status': '',
            'delivery_error': 'Job not found.',
        }
    return {
        'job_id': str(job['_id']),
        'status': job.get('status') or '',
        'delivery_status': job.get('delivery_status') or '',
        'delivery_error': job.get('delivery_error') or '',
    }


def _report_row(document, subscription, web_database, now, manager_user_id=None):
    profile = subscription.get('report_profile') or {}
    emails = subscription.get('emails') or [subscription.get('email')]
    emails = [email for email in emails if email]
    next_run_at = _parse_time(profile.get('next_run_at'))
    due = bool(
        profile.get('enabled')
        and profile.get('schedule_enabled')
        and (next_run_at is None or next_run_at <= now)
    )
    last_job_id = profile.get('last_job_id') or ''
    return {
        'username': subscription.get('username') or '',
        'emails': emails,
        'delivery_mode': subscription.get('delivery_mode') or 'individual',
        'email': ', '.join(emails),
        'team': subscription.get('team') or '',
        'enabled': bool(profile.get('enabled')),
        'schedule_enabled': bool(profile.get('schedule_enabled')),
        'schedule_weekday': profile.get('schedule_weekday') or '',
        'schedule_time': profile.get('schedule_time') or '',
        'generation_mode': profile.get('generation_mode') or '',
        'report_language': profile.get('report_language') or '',
        'next_run_at': _iso(next_run_at),
        'due': due,
        'last_run_at': _iso(profile.get('last_run_at')),
        'last_error': profile.get('last_error') or '',
        'last_job_id': str(last_job_id) if last_job_id else '',
        'last_match_count': profile.get('last_match_count'),
        'schedule_claim_owner': document.get('schedule_claim_owner') or '',
        'schedule_claim_until': _iso(document.get('schedule_claim_until')),
        'delivery': _job_delivery(web_database, last_job_id, manager_user_id),
    }


def _newsletter_row(subscription, web_database, manager_user_id=None):
    profile = subscription.get('newsletter_profile') or {}
    emails = subscription.get('emails') or [subscription.get('email')]
    emails = [email for email in emails if email]
    email = ', '.join(emails)
    if profile.get('enabled'):
        if manager_user_id is None:
            stats = newsletter_delivery_statistics(emails, web_database)
        else:
            stats = newsletter_delivery_statistics(
                emails,
                web_database,
                manager_user_id=manager_user_id,
            )
    else:
        stats = {
            'email': email,
            'total': 0,
            'by_collection': [],
            'databases': [],
        }
    return {
        'username': subscription.get('username') or '',
        'emails': emails,
        'delivery_mode': subscription.get('delivery_mode') or 'individual',
        'email': email,
        'team': subscription.get('team') or '',
        'enabled': bool(profile.get('enabled')),
        'delivery_cursor': profile.get('delivery_cursor') or '',
        'cve_delivery_cutoff': profile.get('cve_delivery_cutoff') or '',
        'total_delivered': int(stats.get('total') or 0),
        'by_collection': stats.get('by_collection') or [],
    }


def _recent_newsletter_deliveries(web_database, manager_user_id=None):
    query = {} if manager_user_id is None else {'managed_by_user_id': manager_user_id}
    cursor = web_database[NEWSLETTER_DELIVERIES].find(query).sort('sent_at', -1).limit(RECENT_NEWSLETTER_LIMIT)
    rows = []
    for item in cursor:
        rows.append({
            'email': item.get('email') or '',
            'source_collection': item.get('source_collection') or '',
            'selection_id': item.get('selection_id') or '',
            'title': item.get('title') or '',
            'database': item.get('database') or '',
            'sent_at': _iso(item.get('sent_at')),
        })
    return rows


def build_health_snapshot(web_database, vuln_database, now=None, manager_user_id=None):
    now = now or datetime.now(timezone.utc)
    scheduler = read_scheduler_health(web_database, now=now)
    reports = []
    newsletters = []
    query = {} if manager_user_id is None else {'managed_by_user_id': manager_user_id}
    for document in web_database['sub_account'].find(query):
        try:
            subscription = normalize_subscription(vuln_database, document)
        except ValueError:
            continue
        reports.append(_report_row(document, subscription, web_database, now, manager_user_id))
        newsletters.append(_newsletter_row(subscription, web_database, manager_user_id))
    reports.sort(key=lambda row: (not row['due'], row['email']))
    newsletters.sort(key=lambda row: row['email'])
    return {
        'generated_at': now.isoformat(),
        'scheduler': scheduler,
        'reports': reports,
        'newsletters': newsletters,
        'recent_newsletter_deliveries': _recent_newsletter_deliveries(
            web_database, manager_user_id,
        ),
    }

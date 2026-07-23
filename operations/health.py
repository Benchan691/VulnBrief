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


def _job_delivery(web_database, job_id):
    if not job_id:
        return None
    try:
        job = web_database['report_jobs'].find_one({'_id': ObjectId(str(job_id))})
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


def _report_row(document, subscription, web_database, now):
    profile = subscription.get('report_profile') or {}
    next_run_at = _parse_time(profile.get('next_run_at'))
    due = bool(
        profile.get('enabled')
        and profile.get('schedule_enabled')
        and (next_run_at is None or next_run_at <= now)
    )
    last_job_id = profile.get('last_job_id') or ''
    return {
        'email': subscription.get('email') or '',
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
        'delivery': _job_delivery(web_database, last_job_id),
    }


def _newsletter_row(subscription, web_database):
    profile = subscription.get('newsletter_profile') or {}
    email = subscription.get('email') or ''
    stats = newsletter_delivery_statistics(email, web_database) if profile.get('enabled') else {
        'email': email,
        'total': 0,
        'by_collection': [],
        'databases': [],
    }
    return {
        'email': email,
        'team': subscription.get('team') or '',
        'enabled': bool(profile.get('enabled')),
        'delivery_cursor': profile.get('delivery_cursor') or '',
        'cve_delivery_cutoff': profile.get('cve_delivery_cutoff') or '',
        'total_delivered': int(stats.get('total') or 0),
        'by_collection': stats.get('by_collection') or [],
    }


def _recent_newsletter_deliveries(web_database):
    cursor = web_database[NEWSLETTER_DELIVERIES].find({}).sort('sent_at', -1).limit(RECENT_NEWSLETTER_LIMIT)
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


def build_health_snapshot(web_database, vuln_database, now=None):
    now = now or datetime.now(timezone.utc)
    scheduler = read_scheduler_health(web_database, now=now)
    reports = []
    newsletters = []
    for document in web_database['sub_account'].find({}):
        try:
            subscription = normalize_subscription(vuln_database, document)
        except ValueError:
            continue
        reports.append(_report_row(document, subscription, web_database, now))
        newsletters.append(_newsletter_row(subscription, web_database))
    reports.sort(key=lambda row: (not row['due'], row['email']))
    newsletters.sort(key=lambda row: row['email'])
    return {
        'generated_at': now.isoformat(),
        'scheduler': scheduler,
        'reports': reports,
        'newsletters': newsletters,
        'recent_newsletter_deliveries': _recent_newsletter_deliveries(web_database),
    }

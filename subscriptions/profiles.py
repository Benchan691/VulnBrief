import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from core.database import get_web_database
from reviews.repository import MAX_EXPORT_SELECTIONS, review_views


SUB_ACCOUNT_COLLECTION = 'sub_account'


def get_sub_account_collection():
    return get_web_database()[SUB_ACCOUNT_COLLECTION]


def ensure_sub_account_collection():
    database = get_web_database()
    if SUB_ACCOUNT_COLLECTION in database.list_collection_names():
        return
    database.create_collection(SUB_ACCOUNT_COLLECTION)


HONG_KONG = ZoneInfo('Asia/Hong_Kong')
FILTER_TEXT_FIELDS = (
    'search', 'code', 'title', 'impact', 'affected', 'source',
)
KEYWORD_SEARCH_FIELDS = (
    'code', 'cve', 'title', 'description', 'impacts', 'affected',
    'recommendation', 'related_link', 'status', 'source_provider',
    'details.cve.affected.vendor',
    'details.cve.affected_products.vendor', 'vendor',
    'details.cve.affected.product',
    'details.cve.affected_products.product', 'affected_products',
)
VALID_SEVERITIES = {'', 'Critical', 'High', 'Medium', 'Low'}
VALID_WINDOWS = {'all', 'daily', 'week', 'custom'}
VALID_GENERATION_MODES = {'template', 'enriched_weekly'}
VALID_LANGUAGES = {'en', 'zh', 'ch'}
VALID_WEEKDAYS = {'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'}

DEFAULT_FILTERS = {
    'collections': [],
    'search': '',
    'code': '',
    'title': '',
    'impact': '',
    'affected': '',
    'status': [],
    'severity_threshold': '',
    'include_unknown': False,
    'source': '',
    'keywords': [],
    'time_window': 'all',
    'start': '',
    'end': '',
    'source_timestamp': {},
    'report_scope': {},
}
DEFAULT_NEWSLETTER_PROFILE = {
    'enabled': False,
    'filters': DEFAULT_FILTERS,
    'delivery_cursor': '',
}
DEFAULT_REPORT_PROFILE = {
    'enabled': True,
    'filters': DEFAULT_FILTERS,
    'generation_mode': 'template',
    'report_language': 'en',
    'schedule_enabled': False,
    'schedule_weekday': 'mon',
    'schedule_time': '09:00',
}


def parse_hong_kong_datetime(value):
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=HONG_KONG)
    return parsed.astimezone(HONG_KONG)


_parse_datetime = parse_hong_kong_datetime


def parse_include_unknown(value):
    if value is None:
        return False
    return str(value).lower() in {'1', 'true', 'yes', 'on'}


def build_scraped_at_window(window, start='', end='', now=None):
    if window not in VALID_WINDOWS:
        raise ValueError('Invalid scrape time window.')
    if window == 'all':
        return None

    now = (now or datetime.now(timezone.utc)).astimezone(HONG_KONG)
    if window == 'daily':
        bounds = (now.replace(hour=0, minute=0, second=0, microsecond=0), now)
    elif window == 'week':
        bounds = (now - timedelta(days=7), now)
    else:
        start_dt = parse_hong_kong_datetime(start)
        end_dt = parse_hong_kong_datetime(end)
        if start_dt is None or end_dt is None or start_dt >= end_dt:
            raise ValueError('Custom scrape time requires a valid start before end.')
        bounds = (start_dt, end_dt)

    start_dt, end_dt = bounds
    return {
        'scraped_at': {
            '$gte': start_dt.astimezone(timezone.utc).isoformat(),
            '$lt': end_dt.astimezone(timezone.utc).isoformat(),
        },
    }


def validate_filters(database, value):
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError('Filters must be an object.')
    filters = deepcopy(DEFAULT_FILTERS)
    collections = value.get('collections', [])
    if not isinstance(collections, list):
        raise ValueError('Filter collections must be a list.')
    valid_views = review_views(database)
    if any(not isinstance(name, str) or name not in valid_views for name in collections):
        raise ValueError('Filters contain an invalid review collection.')
    filters['collections'] = list(dict.fromkeys(collections))
    for field in FILTER_TEXT_FIELDS:
        raw = value.get(field, '')
        if raw is not None and not isinstance(raw, str):
            raise ValueError(f'Filter {field} must be text.')
        filters[field] = (raw or '').strip()
    raw_status = value.get('status', [])
    include_unknown = value.get('include_unknown', raw_status == 'Unknown')
    if raw_status == 'Unknown':
        raw_status = []
    if isinstance(raw_status, str):
        status = [raw_status] if raw_status else []
    elif isinstance(raw_status, list):
        status = raw_status
    else:
        raise ValueError('Severity/status must be Critical, High, Medium, or Low.')
    if any(not isinstance(item, str) or item not in VALID_SEVERITIES - {''} for item in status):
        raise ValueError('Severity/status must be Critical, High, Medium, or Low.')
    status = list(dict.fromkeys(item for item in status if item))
    severity_threshold = value.get('severity_threshold', '')
    if not isinstance(severity_threshold, str) or severity_threshold not in VALID_SEVERITIES:
        raise ValueError('Severity threshold must be Critical, High, Medium, or Low.')
    if not isinstance(include_unknown, bool):
        raise ValueError('Include unknown must be true or false.')
    filters['status'] = status
    filters['severity_threshold'] = severity_threshold
    filters['include_unknown'] = include_unknown
    filters['time_window'] = value.get('time_window', 'all')
    if filters['time_window'] not in VALID_WINDOWS:
        raise ValueError('Invalid filter time window.')
    filters['start'] = (value.get('start') or '').strip()
    filters['end'] = (value.get('end') or '').strip()
    if filters['time_window'] == 'custom':
        start = parse_hong_kong_datetime(filters['start'])
        end = parse_hong_kong_datetime(filters['end'])
        if start is None or end is None or start >= end:
            raise ValueError('Custom filter window requires a valid start before end.')
    source_timestamp = value.get('source_timestamp') or {}
    if not isinstance(source_timestamp, dict):
        raise ValueError('Source timestamp filter must be an object.')
    filters['source_timestamp'] = dict(source_timestamp)
    report_scope = value.get('report_scope') or {}
    if not isinstance(report_scope, dict):
        raise ValueError('Report scope must be an object.')
    if 'max_count' in report_scope and report_scope['max_count'] not in (None, ''):
        max_count = int(report_scope['max_count'])
        if max_count <= 0 or max_count > MAX_EXPORT_SELECTIONS:
            raise ValueError(f'Report scope max count must be between 1 and {MAX_EXPORT_SELECTIONS}.')
        report_scope['max_count'] = max_count
    if 'kev_only' in report_scope:
        report_scope['kev_only'] = bool(report_scope['kev_only'])
    filters['report_scope'] = report_scope
    keywords = value.get('keywords') or []
    if not isinstance(keywords, list):
        raise ValueError('Keywords must be a list.')
    seen_keywords = set()
    for item in keywords:
        if not isinstance(item, str):
            raise ValueError('Keywords must be text.')
        keyword = item.strip()
        key = re.sub(r'\s+', '', keyword).lower()
        if keyword and key not in seen_keywords:
            seen_keywords.add(key)
            filters['keywords'].append(keyword)
    return filters


def validate_profile(database, value, profile_type):
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError(f'{profile_type.title()} profile must be an object.')
    default = DEFAULT_NEWSLETTER_PROFILE if profile_type == 'newsletter' else DEFAULT_REPORT_PROFILE
    profile = deepcopy(default)
    profile['enabled'] = bool(value.get('enabled', default['enabled']))
    profile['filters'] = validate_filters(database, value.get('filters'))
    if profile_type == 'newsletter':
        if 'delivery_cursor' in value:
            profile['delivery_cursor'] = value.get('delivery_cursor') or ''
        return profile
    if profile_type == 'report':
        profile['generation_mode'] = value.get('generation_mode', default['generation_mode'])
        if profile['generation_mode'] in {'company_ai', 'ai'}:
            profile['generation_mode'] = 'enriched_weekly'
        profile['report_language'] = value.get('report_language', 'en')
        if profile['generation_mode'] not in VALID_GENERATION_MODES:
            raise ValueError('Invalid report generation mode.')
        if profile['report_language'] not in VALID_LANGUAGES:
            raise ValueError('Invalid report language.')
        if profile['generation_mode'] == 'template':
            profile['report_language'] = 'en'
        if profile['generation_mode'] == 'enriched_weekly':
            collections = profile['filters'].get('collections') or []
            if collections and collections != ['cve_review']:
                raise ValueError('enriched_weekly report profiles only support cve_review.')
            profile['filters']['collections'] = ['cve_review']
        profile['schedule_enabled'] = bool(value.get('schedule_enabled', default.get('schedule_enabled', False)))
        profile['schedule_weekday'] = str(value.get('schedule_weekday') or default.get('schedule_weekday', 'mon')).strip().lower()
        profile['schedule_time'] = str(value.get('schedule_time') or default.get('schedule_time', '09:00')).strip()
        if profile['schedule_weekday'] not in VALID_WEEKDAYS:
            raise ValueError('Invalid report schedule weekday.')
        if not re.match(r'^\d{2}:\d{2}$', profile['schedule_time']):
            raise ValueError('Invalid report schedule time.')
        hour, minute = [int(part) for part in profile['schedule_time'].split(':')]
        if hour > 23 or minute > 59:
            raise ValueError('Invalid report schedule time.')
        for field in ('next_run_at', 'last_run_at', 'last_job_id', 'last_error', 'last_match_count'):
            if field in value:
                profile[field] = value[field]
    return profile


def normalize_subscription(database, document):
    normalized = dict(document)
    legacy_collections = document.get('subscriptions', [])
    newsletter_value = document.get('newsletter_profile', {})
    report_value = document.get('report_profile')
    if report_value is None:
        report_value = {
            'enabled': True,
            'filters': {'collections': legacy_collections},
        }
    normalized['newsletter_profile'] = validate_profile(database, newsletter_value, 'newsletter')
    normalized['report_profile'] = validate_profile(database, report_value, 'report')
    normalized.pop('subscriptions', None)
    return normalized


def profile_with_window(profile, window_data):
    profile = deepcopy(profile)
    filters = profile['filters']
    window = window_data.get('window')
    if window:
        filters['time_window'] = window
        filters['start'] = window_data.get('start', '')
        filters['end'] = window_data.get('end', '')
    return profile


import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from croniter import croniter

from review_data import MAX_EXPORT_SELECTIONS, review_views


HONG_KONG = ZoneInfo('Asia/Hong_Kong')
FILTER_TEXT_FIELDS = (
    'search', 'code', 'title', 'impact', 'affected', 'source',
)
VALID_SEVERITIES = {'', 'Critical', 'High', 'Medium', 'Low'}
VALID_WINDOWS = {'all', 'daily', 'week', 'custom'}
VALID_GENERATION_MODES = {'company_ai', 'template'}
VALID_LANGUAGES = {'en', 'zh', 'ch'}

DEFAULT_FILTERS = {
    'collections': [],
    'search': '',
    'code': '',
    'title': '',
    'impact': '',
    'affected': '',
    'status': '',
    'include_unknown': False,
    'source': '',
    'time_window': 'all',
    'start': '',
    'end': '',
}
DEFAULT_NEWSLETTER_PROFILE = {
    'enabled': False,
    'filters': DEFAULT_FILTERS,
}
DEFAULT_REPORT_PROFILE = {
    'enabled': True,
    'filters': DEFAULT_FILTERS,
    'generation_mode': 'company_ai',
    'report_language': 'en',
    'schedule_enabled': False,
    'cron': '0 9 * * 1',
}


def _parse_datetime(value):
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


def validate_cron(value):
    if not isinstance(value, str) or len(value.split()) != 5 or not croniter.is_valid(value):
        raise ValueError('Schedule must be a valid five-field cron expression.')
    return value.strip()


def next_cron_run(value, now=None):
    value = validate_cron(value)
    local_now = (now or datetime.now(timezone.utc)).astimezone(HONG_KONG)
    return croniter(value, local_now).get_next(datetime).astimezone(timezone.utc)


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
    status = value.get('status', '')
    include_unknown = value.get('include_unknown', status == 'Unknown')
    if status == 'Unknown':
        status = ''
    if not isinstance(status, str) or status not in VALID_SEVERITIES:
        raise ValueError('Severity/status must be Critical, High, Medium, or Low.')
    if not isinstance(include_unknown, bool):
        raise ValueError('Include unknown must be true or false.')
    filters['status'] = status
    filters['include_unknown'] = include_unknown
    filters['time_window'] = value.get('time_window', 'all')
    if filters['time_window'] not in VALID_WINDOWS:
        raise ValueError('Invalid filter time window.')
    filters['start'] = (value.get('start') or '').strip()
    filters['end'] = (value.get('end') or '').strip()
    if filters['time_window'] == 'custom':
        start = _parse_datetime(filters['start'])
        end = _parse_datetime(filters['end'])
        if start is None or end is None or start >= end:
            raise ValueError('Custom filter window requires a valid start before end.')
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
    if profile_type == 'report':
        profile['generation_mode'] = value.get('generation_mode', 'company_ai')
        profile['report_language'] = value.get('report_language', 'en')
        profile['schedule_enabled'] = bool(value.get('schedule_enabled', False))
        profile['cron'] = validate_cron(value.get('cron', '0 9 * * 1'))
        if profile['generation_mode'] not in VALID_GENERATION_MODES:
            raise ValueError('Invalid report generation mode.')
        if profile['report_language'] not in VALID_LANGUAGES:
            raise ValueError('Invalid report language.')
        if profile['generation_mode'] == 'template':
            profile['report_language'] = 'en'
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


def _regex(value):
    return {'$regex': re.escape(value), '$options': 'i'}


UNKNOWN_SEVERITY_VALUES = ('unknown', 'n/a', 'na', 'none', 'not specified')


def unknown_severity_clauses():
    return [
        {'severity': {'$exists': False}},
        {'severity': None},
        {'severity': ''},
        *[
            {'severity': {'$regex': f'^{re.escape(value)}$', '$options': 'i'}}
            for value in UNKNOWN_SEVERITY_VALUES
        ],
    ]


def build_severity_filter(status='', include_unknown=False):
    status = (status or '').strip()
    include_unknown = bool(include_unknown)
    if status:
        severity_clause = {'severity': {
            '$regex': f'^{re.escape(status)}(?:\\s+Risk)?$',
            '$options': 'i',
        }}
        return (
            {'$or': [severity_clause, *unknown_severity_clauses()]}
            if include_unknown else severity_clause
        )
    if not include_unknown:
        return {'severity': {
            '$regex': r'^(?:Critical|High|Medium|Low)(?:\s+Risk)?$',
            '$options': 'i',
        }}
    return None


def severity_projection_fields():
    return {
        'status': 1,
        'severity': {
            '$ifNull': [
                '$severity',
                {
                    '$ifNull': [
                        '$details.hkcert.risk_level',
                        {
                            '$ifNull': [
                                '$details.cisco.sir',
                                {
                                    '$ifNull': [
                                        '$details.cnnvd.hazardLevel',
                                        '$status',
                                    ],
                                },
                            ],
                        },
                    ],
                },
            ],
        },
    }


def _window_bounds(filters, now=None):
    now = (now or datetime.now(timezone.utc)).astimezone(HONG_KONG)
    window = filters['time_window']
    if window == 'all':
        return None
    if window == 'daily':
        return now.replace(hour=0, minute=0, second=0, microsecond=0), now
    if window == 'week':
        return now - timedelta(days=7), now
    return _parse_datetime(filters['start']), _parse_datetime(filters['end'])


def build_match_filter(filters, now=None):
    clauses = []
    mapping = {
        'search': ('code', 'cve', 'title', 'description', 'impacts', 'affected',
                   'recommendation', 'related_link', 'status', 'source_provider'),
        'code': ('code', 'cve'),
        'title': ('title',),
        'impact': ('impacts',),
        'affected': ('affected',),
        'source': ('source_provider',),
    }
    for parameter, fields in mapping.items():
        value = filters.get(parameter, '')
        if value:
            clauses.append({'$or': [{field: _regex(value)} for field in fields]})
    status = filters.get('status', '')
    include_unknown = filters.get('include_unknown', False)
    severity_clause = build_severity_filter(status, include_unknown)
    if severity_clause:
        clauses.append(severity_clause)
    bounds = _window_bounds(filters, now)
    if bounds:
        start, end = bounds
        clauses.append({
            'scraped_at': {
                '$gte': start.astimezone(timezone.utc).isoformat(),
                '$lt': end.astimezone(timezone.utc).isoformat(),
            },
        })
    if not clauses:
        return {}
    return clauses[0] if len(clauses) == 1 else {'$and': clauses}


def _projection_pipeline(view):
    pipeline = list(view.get('options', {}).get('pipeline', []))
    if not pipeline or '$project' not in pipeline[0]:
        raise ValueError('Review view must begin with a projection.')
    first = dict(pipeline[0])
    projection = dict(first['$project'])
    projection.update({
        '_id': 1,
        **severity_projection_fields(),
        'vuln_type': 1,
        'scraped_at': 1,
        'disclosure_date': 1,
        'source_provider': '$source.provider',
    })
    first['$project'] = projection
    return [first, *pipeline[1:]]


def query_profile_matches(database, profile, limit=MAX_EXPORT_SELECTIONS, include_documents=False):
    filters = profile['filters']
    views = review_views(database)
    collection_names = filters['collections'] or sorted(views)
    mongo_filter = build_match_filter(filters)
    results = []
    for view_name in collection_names:
        view = views[view_name]
        pipeline = _projection_pipeline(view)
        pipeline.extend([
            {'$match': mongo_filter},
            {'$sort': {'scraped_at': 1, '_id': 1}},
        ])
        if limit is not None:
            pipeline.append({'$limit': limit + 1})
        for document in database[view['options']['viewOn']].aggregate(pipeline):
            selection_id = str(document.pop('_id'))
            item = {
                'collection': view_name,
                'source_collection': view['options']['viewOn'],
                'selection_id': selection_id,
            }
            if include_documents:
                item['document'] = document
            results.append(item)
            if limit is not None and len(results) > limit:
                raise ValueError(f'Filter result exceeds the {limit}-document limit.')
    return results

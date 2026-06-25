import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from mongo import get_web_database
from review_data import MAX_EXPORT_SELECTIONS, review_views


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
    'target_vendor', 'target_product', 'affected_product_name',
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
    'target_vendor': '',
    'target_product': '',
    'affected_product_name': '',
    'time_window': 'all',
    'start': '',
    'end': '',
    'source_timestamp': {},
    'report_scope': {},
    'cpe_pairs': [],
}
DEFAULT_NEWSLETTER_PROFILE = {
    'enabled': False,
    'filters': DEFAULT_FILTERS,
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
    cpe_pairs = value.get('cpe_pairs') or []
    if not isinstance(cpe_pairs, list):
        raise ValueError('CPE filters must be a list.')
    normalized_pairs = []
    seen_pairs = set()
    for item in cpe_pairs:
        if not isinstance(item, dict):
            raise ValueError('CPE filter entries must be objects.')
        vendor = str(item.get('vendor') or '').strip()
        product = str(item.get('product') or '').strip()
        if not vendor:
            raise ValueError('CPE filter entries require a vendor.')
        key = (vendor.lower(), product.lower())
        if key not in seen_pairs:
            seen_pairs.add(key)
            normalized = {'vendor': vendor}
            if product:
                normalized['product'] = product
            normalized_pairs.append(normalized)
    filters['cpe_pairs'] = normalized_pairs
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


def _normalize_status_values(status):
    if isinstance(status, list):
        return [item.strip() for item in status if isinstance(item, str) and item.strip()]
    if isinstance(status, str) and status.strip():
        return [status.strip()]
    return []


def build_severity_filter(status='', include_unknown=False):
    statuses = _normalize_status_values(status)
    include_unknown = bool(include_unknown)
    if statuses:
        severity_clauses = [
            {'severity': {
                '$regex': f'^{re.escape(value)}(?:\\s+Risk)?$',
                '$options': 'i',
            }}
            for value in statuses
        ]
        severity_clause = (
            severity_clauses[0]
            if len(severity_clauses) == 1 else {'$or': severity_clauses}
        )
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


def build_severity_threshold_filter(threshold='', include_unknown=False):
    threshold = (threshold or '').strip()
    if not threshold:
        return None
    order = ['Critical', 'High', 'Medium', 'Low']
    if threshold not in order:
        raise ValueError('Severity threshold must be Critical, High, Medium, or Low.')
    allowed = order[:order.index(threshold) + 1]
    severity_clause = {
        '$or': [
            {'severity': {'$regex': f'^{re.escape(value)}(?:\\s+Risk)?$', '$options': 'i'}}
            for value in allowed
        ],
    }
    if include_unknown:
        return {'$or': [severity_clause, *unknown_severity_clauses()]}
    return severity_clause


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
    return parse_hong_kong_datetime(filters['start']), parse_hong_kong_datetime(filters['end'])


def _broad_text_clause(value, fields):
    terms = [term for term in str(value or '').split() if term]
    if not terms:
        return None
    if len(terms) == 1:
        return {'$or': [{field: _regex(terms[0])} for field in fields]}
    return {
        '$and': [
            {'$or': [{field: _regex(term)} for field in fields]}
            for term in terms
        ],
    }


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
        'target_vendor': (
            'classification.best_vendor', 'classification.vendor',
            'classification.candidate.vendor', 'details.cve.affected.vendor',
            'details.cve.affected_products.vendor', 'vendor',
        ),
        'target_product': (
            'classification.best_product', 'classification.product',
            'classification.candidate.product', 'details.cve.affected.product',
            'details.cve.affected_products.product', 'affected', 'affected_products',
        ),
        'affected_product_name': (
            'classification.best_product', 'classification.candidate.product',
            'details.cve.affected.product', 'details.cve.affected_products.product',
            'affected', 'affected_products',
        ),
    }
    for parameter, fields in mapping.items():
        value = filters.get(parameter, '')
        if value:
            clauses.append(_broad_text_clause(value, fields))
    cpe_pairs = filters.get('cpe_pairs') or []
    if cpe_pairs:
        search_fields = mapping['search'] + mapping['target_vendor'] + mapping['target_product']
        pair_clauses = []
        for pair in cpe_pairs:
            clause_value = pair['vendor']
            if pair.get('product'):
                clause_value += f" {pair['product']}"
            clause = _broad_text_clause(clause_value, search_fields)
            if clause:
                pair_clauses.append(clause)
        clauses.append(pair_clauses[0] if len(pair_clauses) == 1 else {'$or': pair_clauses})
    status = filters.get('status', '')
    include_unknown = filters.get('include_unknown', False)
    severity_clause = build_severity_filter(status, include_unknown)
    if severity_clause:
        clauses.append(severity_clause)
    severity_threshold_clause = build_severity_threshold_filter(
        filters.get('severity_threshold', ''),
        include_unknown,
    )
    if severity_threshold_clause:
        clauses.append(severity_threshold_clause)
    bounds = _window_bounds(filters, now)
    if bounds:
        start, end = bounds
        clauses.append({
            'scraped_at': {
                '$gte': start.astimezone(timezone.utc).isoformat(),
                '$lt': end.astimezone(timezone.utc).isoformat(),
            },
        })
    source_timestamp = filters.get('source_timestamp') or {}
    if source_timestamp:
        source_clause = build_scraped_at_window(
            source_timestamp.get('time_window') or source_timestamp.get('window') or 'all',
            source_timestamp.get('start', ''),
            source_timestamp.get('end', ''),
            now,
        )
        if source_clause:
            bounds_clause = source_clause['scraped_at']
            clauses.append({'$or': [
                {'scraped_at': bounds_clause},
                {'disclosure_date': bounds_clause},
            ]})
    report_scope = filters.get('report_scope') or {}
    if report_scope.get('kev_only'):
        clauses.append({'$or': [
            {'cisa_kev': True},
            {'kev': True},
            {'details.cve.cisa_kev': True},
            {'details.cve.kev': True},
        ]})
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


def _profile_collection_names(database, profile):
    filters = profile['filters']
    views = review_views(database)
    collection_names = filters['collections'] or sorted(views)
    if profile.get('generation_mode') == 'enriched_weekly':
        collection_names = ['cve_review']
    return filters, views, collection_names


def count_profile_matches(database, profile):
    filters, views, collection_names = _profile_collection_names(database, profile)
    mongo_filter = build_match_filter(filters)
    total = 0
    for view_name in collection_names:
        view = views[view_name]
        pipeline = _projection_pipeline(view)
        pipeline.extend([
            {'$match': mongo_filter},
            {'$count': 'count'},
        ])
        count = 0
        for row in database[view['options']['viewOn']].aggregate(pipeline):
            count = int(row.get('count') or 0)
            break
        total += count
    return total


def query_profile_matches(
    database,
    profile,
    limit=MAX_EXPORT_SELECTIONS,
    include_documents=False,
    allow_partial=False,
):
    filters, views, collection_names = _profile_collection_names(database, profile)
    if profile.get('generation_mode') == 'enriched_weekly':
        scope_limit = (filters.get('report_scope') or {}).get('max_count')
        if scope_limit:
            limit = min(limit, int(scope_limit)) if limit is not None else int(scope_limit)
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
                if allow_partial:
                    return results[:limit]
                raise ValueError(f'Filter result exceeds the {limit}-document limit.')
    return results

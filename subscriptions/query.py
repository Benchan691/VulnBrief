import re
from datetime import datetime, timedelta, timezone

from reviews.repository import MAX_EXPORT_SELECTIONS, review_views
from subscriptions.profiles import (
    HONG_KONG,
    KEYWORD_SEARCH_FIELDS,
    build_scraped_at_window,
    parse_hong_kong_datetime,
)


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


def _keyword_clause(value):
    compact = re.sub(r'\s+', '', str(value or '')).lower()
    if not compact:
        return None
    pattern = r'\s*'.join(re.escape(char) for char in compact)
    return {'$or': [{field: {'$regex': pattern, '$options': 'i'}} for field in KEYWORD_SEARCH_FIELDS]}


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
            clauses.append(_broad_text_clause(value, fields))
    keyword_clauses = [
        clause for clause in (_keyword_clause(keyword) for keyword in filters.get('keywords', []))
        if clause
    ]
    if keyword_clauses:
        clauses.append(keyword_clauses[0] if len(keyword_clauses) == 1 else {'$or': keyword_clauses})
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

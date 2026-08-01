import re
from datetime import datetime, timedelta, timezone

from reviews.repository import MAX_EXPORT_SELECTIONS, review_views
from subscriptions.profiles import (
    HONG_KONG,
    LEGACY_KEYWORD_SEARCH_FIELDS,
    build_observed_at_window,
    parse_hong_kong_datetime,
)
from subscriptions.vendor_products import (
    build_vendor_product_candidate_clause,
    compile_vendor_product_matcher,
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
    return {'severity': 1}


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


def _legacy_keyword_clause(value):
    compact = re.sub(r'\s+', '', str(value or '')).lower()
    if not compact:
        return None
    pattern = r'\s*'.join(re.escape(char) for char in compact)
    return {
        '$or': [
            {field: {'$regex': pattern, '$options': 'i'}}
            for field in LEGACY_KEYWORD_SEARCH_FIELDS
        ],
    }


def build_match_filter(filters, now=None):
    clauses = []
    mapping = {
        'search': ('code', 'cve', 'cve_ids', 'title', 'description', 'impacts', 'affected',
                   'recommendation', 'related_link', 'source_url'),
        'code': ('code', 'cve', 'cve_ids'),
        'title': ('title',),
        'impact': ('impacts',),
        'affected': ('affected',),
        'source': ('source_url',),
    }
    for parameter, fields in mapping.items():
        value = filters.get(parameter, '')
        if value:
            clauses.append(_broad_text_clause(value, fields))
    # Keywords remain queryable only for stored legacy profiles and newsletter
    # compatibility. New report profiles are validated against CSV inventory.
    keyword_clauses = [
        clause for clause in (_legacy_keyword_clause(keyword) for keyword in filters.get('keywords', []))
        if clause
    ]
    if keyword_clauses:
        clauses.append(keyword_clauses[0] if len(keyword_clauses) == 1 else {'$or': keyword_clauses})
    vendor_product_clause = build_vendor_product_candidate_clause(
        filters.get('vendor_product_filter'),
    )
    if vendor_product_clause:
        clauses.append(vendor_product_clause)
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
            'observed_at': {
                '$gte': start.astimezone(timezone.utc),
                '$lt': end.astimezone(timezone.utc),
            },
        })
    source_timestamp = filters.get('source_timestamp') or {}
    if source_timestamp:
        source_clause = build_observed_at_window(
            source_timestamp.get('time_window') or source_timestamp.get('window') or 'all',
            source_timestamp.get('start', ''),
            source_timestamp.get('end', ''),
            now,
        )
        if source_clause:
            bounds_clause = source_clause['observed_at']
            clauses.append({'$or': [
                {'observed_at': bounds_clause},
                {'published_at': bounds_clause},
                {'updated_at': bounds_clause},
            ]})
    report_scope = filters.get('report_scope') or {}
    if report_scope.get('kev_only'):
        clauses.append({'$or': [
            {'cisa_kev': True},
            {'kev': True},
            {'details.cisa_kev': True},
            {'details.kev': True},
        ]})
    cve_delivery_cutoff = str(filters.get('cve_delivery_cutoff') or '').strip()
    if cve_delivery_cutoff:
        cutoff = parse_hong_kong_datetime(cve_delivery_cutoff)
        if cutoff:
            clauses.append({'observed_at': {'$gt': cutoff.astimezone(timezone.utc)}})
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
        'observed_at': 1,
        'published_at': 1,
        'updated_at': 1,
        'cve_ids': 1,
        'source_url': {'$ifNull': ['$source.detail_url', '$source.url']},
    })
    for field in (
        'title', 'summary', 'description', 'details', 'vendor', 'product',
        'affected', 'affected_products', 'containers', 'descriptions',
        'systems_affected', 'products', 'impacts',
    ):
        projection.setdefault(field, 1)
    first['$project'] = projection
    return [first, *pipeline[1:]]


def _profile_collection_names(database, profile):
    filters = profile['filters']
    views = review_views(database)
    collection_names = filters['collections'] or sorted(views)
    if profile.get('generation_mode') == 'enriched_weekly':
        collection_names = ['cve_review']
    return filters, views, collection_names


def _inventory_filter(filters):
    value = filters.get('vendor_product_filter') or {}
    return value if value.get('enabled') else None


def _report_scope_limit(profile, filters):
    if profile.get('generation_mode') != 'enriched_weekly':
        return None
    value = (filters.get('report_scope') or {}).get('max_count')
    return int(value) if value else None


def count_profile_matches_by_confidence(database, profile):
    filters, views, collection_names = _profile_collection_names(database, profile)
    mongo_filter = build_match_filter(filters)
    inventory_filter = _inventory_filter(filters)
    inventory_matcher = (
        compile_vendor_product_matcher(inventory_filter)
        if inventory_filter else None
    )
    scope_limit = _report_scope_limit(profile, filters)
    counts = {
        'count': 0,
        'confirmed_count': 0,
        'probable_count': 0,
        'possible_count': 0,
    }
    for view_name in collection_names:
        view = views[view_name]
        pipeline = _projection_pipeline(view)
        pipeline.append({'$match': mongo_filter})
        if inventory_filter:
            pipeline.append({'$sort': {'observed_at': 1, '_id': 1}})
            for document in database[view['options']['viewOn']].aggregate(pipeline):
                match = inventory_matcher(document)
                if not match:
                    continue
                confidence = match['confidence']
                counts['count'] += 1
                counts[f'{confidence}_count'] += 1
                if scope_limit is not None and counts['count'] >= scope_limit:
                    return counts
            continue
        pipeline.append({'$count': 'count'})
        for row in database[view['options']['viewOn']].aggregate(pipeline):
            count = int(row.get('count') or 0)
            if scope_limit is not None:
                count = min(count, max(scope_limit - counts['count'], 0))
            counts['count'] += count
            # With no inventory filter there is no vendor/product confidence
            # distinction; retain the total for backward-compatible consumers.
            counts['confirmed_count'] += count
            break
        if scope_limit is not None and counts['count'] >= scope_limit:
            return counts
    return counts


def count_profile_matches(database, profile):
    return count_profile_matches_by_confidence(database, profile)['count']


def _selection_item(
    document,
    view_name,
    source_collection,
    *,
    inventory_match=None,
    include_document=False,
):
    document = dict(document)
    selection_id = str(document.pop('_id'))
    item = {
        'collection': view_name,
        'source_collection': source_collection,
        'selection_id': selection_id,
    }
    if inventory_match:
        item['vendor_product_match'] = inventory_match
    if include_document:
        item['document'] = document
    return item


def preview_profile_matches(database, profile, sample_limit):
    """Return confidence counts and samples, scanning inventory candidates once."""
    filters, views, collection_names = _profile_collection_names(database, profile)
    inventory_filter = _inventory_filter(filters)
    if not inventory_filter:
        return (
            count_profile_matches_by_confidence(database, profile),
            query_profile_matches(
                database,
                profile,
                limit=sample_limit,
                include_documents=True,
                allow_partial=True,
            ),
        )

    matcher = compile_vendor_product_matcher(inventory_filter)
    mongo_filter = build_match_filter(filters)
    scope_limit = _report_scope_limit(profile, filters)
    counts = {
        'count': 0,
        'confirmed_count': 0,
        'probable_count': 0,
        'possible_count': 0,
    }
    samples = []
    for view_name in collection_names:
        view = views[view_name]
        source_collection = view['options']['viewOn']
        pipeline = _projection_pipeline(view)
        pipeline.extend([
            {'$match': mongo_filter},
            {'$sort': {'observed_at': 1, '_id': 1}},
        ])
        for document in database[source_collection].aggregate(pipeline):
            match = matcher(document)
            if not match:
                continue
            confidence = match['confidence']
            counts['count'] += 1
            counts[f'{confidence}_count'] += 1
            if len(samples) < sample_limit:
                samples.append(_selection_item(
                    document,
                    view_name,
                    source_collection,
                    inventory_match=match,
                    include_document=True,
                ))
            if scope_limit is not None and counts['count'] >= scope_limit:
                return counts, samples
    return counts, samples


def query_profile_matches(
    database,
    profile,
    limit=MAX_EXPORT_SELECTIONS,
    include_documents=False,
    allow_partial=False,
    collection_filter_overrides=None,
):
    filters, views, collection_names = _profile_collection_names(database, profile)
    scope_limit = _report_scope_limit(profile, filters)
    if scope_limit:
        limit = min(limit, scope_limit) if limit is not None else scope_limit
    collection_filter_overrides = collection_filter_overrides or {}
    results = []
    for view_name in collection_names:
        view = views[view_name]
        view_filters = collection_filter_overrides.get(view_name, filters)
        inventory_filter = _inventory_filter(view_filters)
        inventory_matcher = (
            compile_vendor_product_matcher(inventory_filter)
            if inventory_filter else None
        )
        mongo_filter = build_match_filter(view_filters)
        pipeline = _projection_pipeline(view)
        pipeline.extend([
            {'$match': mongo_filter},
            {'$sort': {'observed_at': 1, '_id': 1}},
        ])
        # Inventory matching has a deterministic post-query confidence check.
        # Applying Mongo's limit first could let rejected broad candidates hide
        # a valid paired match later in the result set.
        if limit is not None and not inventory_filter:
            pipeline.append({'$limit': limit + 1})
        for document in database[view['options']['viewOn']].aggregate(pipeline):
            inventory_match = (
                inventory_matcher(document)
                if inventory_filter else None
            )
            if inventory_filter and not inventory_match:
                continue
            results.append(_selection_item(
                document,
                view_name,
                view['options']['viewOn'],
                inventory_match=inventory_match,
                include_document=include_documents,
            ))
            if limit is not None and len(results) > limit:
                if allow_partial or scope_limit is not None:
                    return results[:limit]
                raise ValueError(f'Filter result exceeds the {limit}-document limit.')
    return results

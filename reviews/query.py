import heapq
import re

from bson import json_util
from reviews.normalizer import (
    is_cve_record_document,
    normalize_cve_record_document,
    promote_cve_display_fields,
)
from reviews.repository import review_views
from reviews.scoring import score_review_document
from subscriptions.profiles import (
    VALID_SEVERITIES,
    build_observed_at_window,
    parse_include_unknown,
)
from subscriptions.query import (
    build_severity_filter,
    severity_projection_fields,
)
SUMMARY_FIELDS = (
    'code', 'cve', 'cve_ids', 'title', 'severity',
    'affected', 'affected_products',
)
FILTER_FIELDS = {
    'code': ('code', 'cve', 'cve_ids'),
    'title': ('title',),
    'affected': ('affected', 'affected_products'),
}
TEXT_SEARCH_FIELDS = (
    'code', 'cve', 'cve_ids', 'title', 'severity',
    'affected', 'affected_products', 'description', 'impacts', 'recommendation',
    'vendor', 'product',
    'details.description',
    'details.summary',
    'details.affected.vendor',
    'details.affected.product',
    'details.vulnerability_identifiers.cve_id',
)
CVE_PATTERN = re.compile(r'\b(?:CVE-)?(\d{4}-\d{4,})\b', re.IGNORECASE)
RELATED_CVE_LIMIT_PER_COLLECTION = 100
RELATED_CVE_QUERY_BATCH_SIZE = 50


def _review_views(database):
    return review_views(database)


def _review_view_names(database):
    return sorted(_review_views(database))


def _is_review_view(database, collection_name):
    return collection_name in _review_views(database)


def _regex(value):
    return {'$regex': re.escape(value), '$options': 'i'}


class _MappingFilterArgs:
    def __init__(self, data):
        self._data = data if isinstance(data, dict) else {}

    def get(self, key, default=''):
        value = self._data.get(key, default)
        if value is None:
            return default
        return value

    def getlist(self, key):
        value = self._data.get(key, [])
        if isinstance(value, list):
            return [str(item) for item in value]
        if value not in (None, ''):
            return [str(value)]
        return []

    def __contains__(self, key):
        return key in self._data


def _build_filter(args):
    clauses = []
    search = args.get('search', '').strip()

    for parameter, fields in FILTER_FIELDS.items():
        value = args.get(parameter, '').strip()
        if value:
            clauses.append({'$or': [{field: _regex(value)} for field in fields]})

    raw_statuses = args.getlist('status') if hasattr(args, 'getlist') else args.get('status', '')
    statuses = raw_statuses if isinstance(raw_statuses, list) else [raw_statuses]
    normalized_statuses = [str(status).strip() for status in statuses if str(status).strip()]
    invalid_statuses = [
        status for status in normalized_statuses
        if status not in VALID_SEVERITIES - {''}
    ]
    if invalid_statuses:
        raise ValueError('Severity must be Critical, High, Medium, or Low.')
    if clauses or search or 'status' in args or 'include_unknown' in args:
        severity_clause = build_severity_filter(
            normalized_statuses,
            parse_include_unknown(args.get('include_unknown')),
        )
        if severity_clause:
            clauses.append(severity_clause)
    time_clause = build_observed_at_window(
        args.get('time_window', 'all').strip() or 'all',
        args.get('start', ''),
        args.get('end', ''),
    )
    if time_clause:
        clauses.append(time_clause)

    if not clauses:
        return {}
    if len(clauses) == 1:
        return clauses[0]
    return {'$and': clauses}


def _serialize(document):
    return json_util.loads(json_util.dumps(document))


def _summary_text(value):
    if value is None:
        return ''
    if isinstance(value, list):
        return ' '.join(_summary_text(item) for item in value)
    if isinstance(value, dict):
        return ' '.join(_summary_text(item) for item in value.values())
    return str(value)


def _first_summary_value(document, fields):
    for field in fields:
        value = _summary_text(document.get(field)).strip()
        if value:
            return value
    return ''


def _extract_cve_ids(document):
    values = [document.get(field) for field in SUMMARY_FIELDS]
    values.append(document.get('cve_ids'))
    details = document.get('details')
    if isinstance(details, dict):
        for field in ('cve_id', 'cve_ids', 'cveCode', 'cveId', 'vulnerability_identifiers'):
            values.append(details.get(field))
    text = ' '.join(_summary_text(value) for value in values)
    seen = set()
    codes = []
    for match in CVE_PATTERN.findall(text):
        code = f'CVE-{match.upper()}'
        if code not in seen:
            seen.add(code)
            codes.append(code)
    return codes


def _search_terms(search):
    return [term for term in search.split() if term]


def _document_matches_search(document, search):
    if not search:
        return True
    haystack = _summary_text(document).casefold()
    terms = _search_terms(search)
    if not terms:
        return True
    return any(term.casefold() in haystack for term in terms)


def _build_text_search_filter(search):
    terms = _search_terms(search)
    if not terms:
        return None
    return {
        '$or': [
            {field: _regex(term)}
            for term in terms
            for field in TEXT_SEARCH_FIELDS
        ],
    }


def _merge_mongo_filters(*filters):
    clauses = [clause for clause in filters if clause]
    if not clauses:
        return {}
    if len(clauses) == 1:
        return clauses[0]
    return {'$and': clauses}


def _combined_mongo_filter(mongo_filter, search):
    return _merge_mongo_filters(mongo_filter, _build_text_search_filter(search))


def _selection_key(collection, selection_id):
    return f'{collection}\u0000{selection_id}'


def _source_projection(view):
    source_name = view.get('options', {}).get('viewOn', '')
    if source_name == 'cve':
        projection = {
            '_id': 1,
            'title': 1,
            'code': 1,
            'cve': 1,
            'details': 1,
            'observed_at': 1,
            'published_at': 1,
            'updated_at': 1,
            'cve_ids': 1,
            'affected': 1,
            'affected_products': 1,
            'description': 1,
            'impacts': 1,
            'recommendation': 1,
            'related_link': 1,
            'references': 1,
        }
        projection.update(severity_projection_fields())
        return [{'$project': projection}]

    pipeline = list(view.get('options', {}).get('pipeline', []))
    if not pipeline or '$project' not in pipeline[0]:
        raise ValueError('Review view must begin with a projection.')

    first_stage = dict(pipeline[0])
    projection = dict(first_stage['$project'])
    projection['_id'] = 1
    if 'code' not in projection:
        projection['code'] = {
            '$ifNull': [
                {
                    '$convert': {
                        'input': '$code',
                        'to': 'string',
                        'onError': '',
                        'onNull': '',
                    },
                },
                '',
            ],
        }
    first_stage['$project'] = projection
    projection.update(severity_projection_fields())
    projection['details'] = 1
    projection['observed_at'] = 1
    projection['published_at'] = 1
    projection['updated_at'] = 1
    projection['cve_ids'] = 1
    return [first_stage, *pipeline[1:]]


def _review_sort_key(document):
    return (document.get('observed_at') or '', str(document.get('_id', '')))


class _ReviewHeapEntry:
    __slots__ = ('sort_key', 'seq', 'name', 'document', 'iterator')

    def __init__(self, sort_key, seq, name, document, iterator):
        self.sort_key = sort_key
        self.seq = seq
        self.name = name
        self.document = document
        self.iterator = iterator

    def __lt__(self, other):
        if self.sort_key != other.sort_key:
            return self.sort_key > other.sort_key
        return self.seq > other.seq


def _sorted_review_pipeline(view, mongo_filter):
    pipeline = _source_projection(view)
    pipeline.extend([
        {'$match': mongo_filter},
        {'$sort': {'observed_at': -1, '_id': -1}},
    ])
    return pipeline


def _query_review_slice(database, view, mongo_filter, skip, limit):
    source_name = view['options']['viewOn']
    pipeline = _sorted_review_pipeline(view, mongo_filter)
    pipeline.append({
        '$facet': {
            'documents': [
                {'$skip': skip},
                {'$limit': limit},
            ],
            'metadata': [{'$count': 'total'}],
        },
    })
    result = next(database[source_name].aggregate(pipeline), None) or {}
    total = (result.get('metadata') or [{}])[0].get('total', 0)
    documents = result.get('documents', [])
    return total, documents


def _iter_collection_documents(database, view, mongo_filter):
    source_name = view['options']['viewOn']
    pipeline = _sorted_review_pipeline(view, mongo_filter)
    yield from database[source_name].aggregate(pipeline)


def _iter_merged_documents(database, views, view_names, mongo_filter):
    heap = []
    for seq, name in enumerate(view_names):
        iterator = iter(_iter_collection_documents(database, views[name], mongo_filter))
        try:
            document = next(iterator)
        except StopIteration:
            continue
        heapq.heappush(
            heap,
            _ReviewHeapEntry(_review_sort_key(document), seq, name, document, iterator),
        )

    while heap:
        entry = heapq.heappop(heap)
        yield entry.name, entry.document
        try:
            next_document = next(entry.iterator)
        except StopIteration:
            continue
        heapq.heappush(
            heap,
            _ReviewHeapEntry(
                _review_sort_key(next_document),
                entry.seq,
                entry.name,
                next_document,
                entry.iterator,
            ),
        )


def _prepare_review_document(collection_name, document, view=None):
    document = dict(document)
    source_name = (view or {}).get('options', {}).get('viewOn', '')
    if source_name == 'cve' or collection_name == 'cve_review' or is_cve_record_document(document):
        document = normalize_cve_record_document(document)
    else:
        document = promote_cve_display_fields(document)
    return document


def _review_response_row(collection_name, document, view=None):
    document = _prepare_review_document(collection_name, document, view)
    scored = score_review_document(document)
    return {
        'collection': collection_name,
        'selection_id': str(document.pop('_id')),
        'document': _serialize(document),
        'selection_score': scored['selection_score'],
        'patch_priority': scored['patch_priority'],
    }


def _merged_review_row(collection_name, document, view=None):
    document = _prepare_review_document(collection_name, document, view)
    sort_key = _review_sort_key(document)
    selection_id = str(document.pop('_id'))
    return {
        'collection': collection_name,
        'selection_id': selection_id,
        'document': _serialize(document),
        '_sort': sort_key,
    }


def _merged_review_rows(database, views, view_names, mongo_filter, search=''):
    rows = []
    for name, document in _iter_merged_documents(database, views, view_names, mongo_filter):
        if not _document_matches_search(document, search):
            continue
        rows.append(_merged_review_row(name, document, views[name]))
    return rows


def _collect_scored_review_rows(database, views, view_names, mongo_filter, search=''):
    combined_filter = _combined_mongo_filter(mongo_filter, search)
    rows = []
    for name, document in _iter_merged_documents(database, views, view_names, combined_filter):
        prepared = _prepare_review_document(name, document, views[name])
        scored = score_review_document(prepared)
        rows.append({
            'collection': name,
            'selection_id': str(prepared.pop('_id')),
            'selection_score': scored['selection_score'],
            'patch_priority': scored['patch_priority'],
            'cve_id': scored['cve_id'],
            'severity': scored['severity'],
            'published_at': scored['published_at'],
            'observed_at': scored['observed_at'],
        })
    return rows


def _paginated_merged_rows(database, views, view_names, mongo_filter, search, skip, limit):
    total = 0
    page_rows = []
    for name, document in _iter_merged_documents(database, views, view_names, mongo_filter):
        if not _document_matches_search(document, search):
            continue
        total += 1
        if total <= skip:
            continue
        if len(page_rows) < limit:
            page_rows.append(_review_response_row(name, document, views[name]))
    return total, page_rows


def _paginated_cve_search_rows(database, views, view_names, mongo_filter, search, skip, limit):
    combined_filter = _combined_mongo_filter(mongo_filter, search)
    if len(view_names) == 1:
        collection_name = view_names[0]
        view = views[collection_name]
        total, documents = _query_review_slice(
            database,
            view,
            combined_filter,
            skip,
            limit,
        )
        return total, [
            _review_response_row(collection_name, document, view)
            for document in documents
        ]
    return _paginated_merged_rows(
        database,
        views,
        view_names,
        combined_filter,
        '',
        skip,
        limit,
    )


def _collect_row_cve_ids(rows):
    row_codes = []
    all_codes = set()
    for row in rows:
        codes = _extract_cve_ids(row['document'])
        row_codes.append(codes)
        all_codes.update(codes)
    return row_codes, all_codes

import heapq
import re
from datetime import datetime, timezone

from bson import json_util
from flask import Response, current_app, jsonify, render_template, request, session
from pymongo.errors import PyMongoError

from mongo import get_vulnerabilities_database
from review_data import (
    MAX_EXPORT_SELECTIONS,
    canonical_selection_id,
    is_cve_record_document,
    normalize_cve_record_document,
    promote_cve_display_fields,
    resolve_vulnerability_document,
    review_views,
)
from subscription_data import (
    VALID_SEVERITIES,
    build_scraped_at_window,
    build_severity_filter,
    parse_include_unknown,
    severity_projection_fields,
)
from . import review_blueprint
from .common import login_required


SUMMARY_FIELDS = (
    'code', 'cve', 'cve_code', 'cve_codes', 'title', 'severity', 'status',
    'affected', 'affected_products',
)
FILTER_FIELDS = {
    'code': ('code', 'cve', 'cve_code', 'cve_codes'),
    'title': ('title',),
    'affected': ('affected', 'affected_products'),
}
TEXT_SEARCH_FIELDS = (
    'code', 'cve', 'cve_code', 'cve_codes', 'title', 'severity', 'status',
    'affected', 'affected_products', 'description', 'impacts', 'recommendation',
    'classification.vendor', 'classification.best_vendor',
    'classification.candidate.vendor',
    'classification.product', 'classification.best_product',
    'classification.candidate.product',
    'details.source.description',
    'details.cve.description',
    'details.description',
    'details.summary',
    'containers.cna.descriptions.value',
    'details.cve.affected.vendor',
    'details.cve.affected.product',
    'details.hkcert.vulnerability_identifiers.cve_id',
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


def _build_filter(args):
    clauses = []
    search = args.get('search', '').strip()

    for parameter, fields in FILTER_FIELDS.items():
        value = args.get(parameter, '').strip()
        if value:
            clauses.append({'$or': [{field: _regex(value)} for field in fields]})

    status = args.get('status', '').strip()
    if status and status not in VALID_SEVERITIES - {''}:
        raise ValueError('Severity must be Critical, High, Medium, or Low.')
    if clauses or search or 'status' in args or 'include_unknown' in args:
        severity_clause = build_severity_filter(
            status,
            parse_include_unknown(args.get('include_unknown')),
        )
        if severity_clause:
            clauses.append(severity_clause)
    time_clause = build_scraped_at_window(
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


def _extract_cve_codes(document):
    values = [document.get(field) for field in SUMMARY_FIELDS]
    values.append(document.get('related_cves'))
    details = document.get('details')
    if isinstance(details, dict):
        for detail in details.values():
            if not isinstance(detail, dict):
                continue
            for field in ('cve_id', 'cve_ids', 'cveCode', 'vulnerability_identifiers'):
                values.append(detail.get(field))
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


def _cve_code_forms(code):
    canonical = code.upper()
    bare = canonical.removeprefix('CVE-')
    return (canonical, bare)


def _selection_key(collection, selection_id):
    return f'{collection}\u0000{selection_id}'


def _source_projection(view):
    source_name = view.get('options', {}).get('viewOn', '')
    if source_name == 'cve':
        projection = {
            '_id': 1,
            'cveMetadata': 1,
            'containers': 1,
            'title': 1,
            'code': 1,
            'cve': 1,
            'details': 1,
            'scraped_at': 1,
            'disclosure_date': 1,
            'classification': 1,
            'cve_code': 1,
            'cve_codes': 1,
            'related_cves': 1,
            'related_cve_ids': 1,
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
    projection['scraped_at'] = 1
    projection['disclosure_date'] = 1
    projection['cve_code'] = 1
    projection['cve_codes'] = 1
    projection['related_cves'] = 1
    projection['related_cve_ids'] = 1
    projection['classification'] = 1
    return [first_stage, *pipeline[1:]]


def _review_sort_key(document):
    return (document.get('scraped_at') or '', str(document.get('_id', '')))


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
        {'$sort': {'scraped_at': -1, '_id': -1}},
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
    return {
        'collection': collection_name,
        'selection_id': str(document.pop('_id')),
        'document': _serialize(document),
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


def _collect_row_cve_codes(rows):
    row_codes = []
    all_codes = set()
    for row in rows:
        codes = _extract_cve_codes(row['document'])
        row_codes.append(codes)
        all_codes.update(codes)
    return row_codes, all_codes


@review_blueprint.route('/reviews')
@login_required
def reviews():
    return render_template('reviews.html')


@review_blueprint.route('/reviews/<collection_name>')
@login_required
def review_collection(collection_name):
    try:
        if not _is_review_view(get_vulnerabilities_database(), collection_name):
            return render_template(
                'review_collection.html',
                collection_name=collection_name,
                initial_error='Review collection not found.',
            ), 404
    except PyMongoError:
        return render_template(
            'review_collection.html',
            collection_name=collection_name,
            initial_error='Unable to connect to the vulnerabilities database.',
        ), 503

    return render_template(
        'review_collection.html',
        collection_name=collection_name,
        initial_error=None,
    )


@review_blueprint.route('/api/reviews')
@login_required
def get_review_collections():
    try:
        database = get_vulnerabilities_database()
        view_names = _review_view_names(database)
        data = [
            {
                'name': name,
                'source': name[:-len(current_app.config['REVIEW_VIEW_SUFFIX'])],
                'count': database[name].count_documents({}),
            }
            for name in view_names
        ]
        return jsonify({'data': data})
    except PyMongoError as exc:
        return jsonify({'error': 'Unable to connect to the vulnerabilities database.'}), 503


def _view_source_name(view):
    return view['options']['viewOn']


def _selected_review_collections(args, views):
    mode = args.get('mode', '').strip().lower()
    if mode == 'non_cve':
        raise ValueError('Only CVE review documents are supported.')
    if mode not in {'', 'cve'}:
        raise ValueError('Review mode must be cve.')
    return sorted(
        name for name, view in views.items() if _view_source_name(view) == 'cve'
    )


def _related_summary(collection_name, selection_id, document, current_collection, current_selection_id):
    return {
        'collection': collection_name,
        'selection_id': selection_id,
        'document': _serialize(document),
        'code': _first_summary_value(document, ('code', 'cve', 'cve_code', 'cve_codes')),
        'title': _first_summary_value(document, ('title',)),
        'severity': _first_summary_value(document, ('severity', 'status', 'impacts')),
        'affected': _first_summary_value(document, ('affected', 'affected_products')),
        'is_self': collection_name == current_collection and selection_id == current_selection_id,
    }


def _related_cve_mongo_filter(cve_codes):
    return {'$or': [
        {field: {'$regex': f'^{re.escape(form)}$', '$options': 'i'}}
        for code in cve_codes
        for form in _cve_code_forms(code)
        for field in (
            'code',
            'cve',
            'cve_code',
            'cve_codes',
            'related_cves.cve_code',
            'details.hkcert.vulnerability_identifiers.cve_id',
        )
    ]}


def _related_candidates(database, views, cve_codes):
    all_codes = set(cve_codes)
    if not all_codes:
        return []
    candidates = []
    ordered_codes = sorted(all_codes)

    for start in range(0, len(ordered_codes), RELATED_CVE_QUERY_BATCH_SIZE):
        batch_codes = ordered_codes[start:start + RELATED_CVE_QUERY_BATCH_SIZE]
        mongo_filter = _related_cve_mongo_filter(batch_codes)
        for name in sorted(views):
            _, documents = _query_review_slice(
                database,
                views[name],
                mongo_filter,
                0,
                RELATED_CVE_LIMIT_PER_COLLECTION,
            )
            for document in documents:
                sort_key = _review_sort_key(document)
                selection_id = str(document.pop('_id'))
                candidates.append({
                    'collection': name,
                    'selection_id': selection_id,
                    'document': document,
                    'codes': set(_extract_cve_codes(document)),
                    '_sort': sort_key,
                })
    return candidates


def _related_for_codes(candidates, codes, current_collection, current_selection_id):
    code_set = set(codes)
    if not code_set:
        return []

    related = []
    seen = set()
    for candidate in candidates:
        if not code_set.intersection(candidate['codes']):
            continue
        key = (candidate['collection'], candidate['selection_id'])
        if key in seen:
            continue
        seen.add(key)
        related.append({
            **_related_summary(
                candidate['collection'],
                candidate['selection_id'],
                candidate['document'],
                current_collection,
                current_selection_id,
            ),
            '_sort': candidate['_sort'],
        })

    related.sort(key=lambda item: (item['is_self'], item['_sort']), reverse=True)
    return related


def _attach_related_cve_documents(database, views, rows):
    if not rows:
        return

    row_codes, all_codes = _collect_row_cve_codes(rows)
    candidates = _related_candidates(database, views, all_codes)
    for row, codes in zip(rows, row_codes):
        related = _related_for_codes(
            candidates,
            codes,
            row['collection'],
            row['selection_id'],
        )
        for item in related:
            item.pop('_sort', None)
        row['related'] = related


def _filtered_cve_rows(database, views, mongo_filter, search):
    cve_names = sorted(
        name for name, view in views.items() if _view_source_name(view) == 'cve'
    )
    return _merged_review_rows(database, views, cve_names, mongo_filter, search)


@review_blueprint.route('/api/reviews/search')
@login_required
def search_review_documents():
    try:
        mongo_filter = _build_filter(request.args)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    try:
        database = get_vulnerabilities_database()
        views = _review_views(database)
        view_names = _selected_review_collections(request.args, views)
        mode = request.args.get('mode', '').strip().lower()
        search = request.args.get('search', '').strip()

        page = max(request.args.get('page', 1, type=int), 1)
        page_size = min(max(request.args.get('page_size', 25, type=int), 1), 100)
        global_skip = (page - 1) * page_size

        total, data = _paginated_cve_search_rows(
            database,
            views,
            view_names,
            mongo_filter,
            search,
            global_skip,
            page_size,
        )
        if mode == 'cve':
            _attach_related_cve_documents(database, views, data)

        return jsonify({
            'data': data,
            'page': page,
            'page_size': page_size,
            'total': total,
            'pages': max((total + page_size - 1) // page_size, 1),
        })
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError as exc:
        return jsonify({'error': 'Unable to query the vulnerabilities database.'}), 503
    except Exception:
        current_app.logger.exception('Unexpected review search failure.')
        return jsonify({'error': 'Unable to search review documents.'}), 500


@review_blueprint.route('/api/reviews/<collection_name>')
@login_required
def get_review_documents(collection_name):
    try:
        database = get_vulnerabilities_database()
        view = _review_views(database).get(collection_name)
        if view is None:
            return jsonify({'error': 'Review collection not found.'}), 404

        page = max(request.args.get('page', 1, type=int), 1)
        page_size = min(max(request.args.get('page_size', 25, type=int), 1), 100)
        mongo_filter = _build_filter(request.args)
        total, documents = _query_review_slice(
            database,
            view,
            mongo_filter,
            (page - 1) * page_size,
            page_size,
        )
        documents = [
            _prepare_review_document(collection_name, document, view)
            for document in documents
        ]

        return jsonify({
            'data': [
                {
                    'selection_id': str(document.pop('_id')),
                    'document': _serialize(document),
                }
                for document in documents
            ],
            'page': page,
            'page_size': page_size,
            'total': total,
            'pages': max((total + page_size - 1) // page_size, 1),
        })
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to query the vulnerabilities database.'}), 503


@review_blueprint.route('/api/reviews/export-json', methods=['POST'])
@login_required
def export_review_documents():
    data = request.get_json(silent=True) or {}
    selections = data.get('selections')
    if not isinstance(selections, list) or not selections:
        return jsonify({'error': 'Select at least one document to export.'}), 400
    if len(selections) > MAX_EXPORT_SELECTIONS:
        return jsonify({
            'error': f'Export is limited to {MAX_EXPORT_SELECTIONS} documents.',
        }), 400

    try:
        database = get_vulnerabilities_database()
        views = _review_views(database)
        documents = []

        for selection in selections:
            if not isinstance(selection, dict):
                return jsonify({'error': 'Invalid selection.'}), 400

            collection_name = selection.get('collection')
            selection_id = selection.get('selection_id')
            if not isinstance(collection_name, str) or not isinstance(selection_id, str):
                return jsonify({'error': 'Invalid selection.'}), 400

            view = views.get(collection_name)
            if view is None:
                return jsonify({'error': f'Invalid review collection: {collection_name}.'}), 400

            source_name = view['options']['viewOn']
            document = resolve_vulnerability_document(database, source_name, selection_id)
            if document is None:
                return jsonify({'error': f'Selected document was not found: {selection_id}.'}), 404
            document['_id'] = canonical_selection_id(document)
            documents.append(document)

        filename = datetime.now(timezone.utc).strftime(
            'vulnerability-export-%Y%m%dT%H%M%SZ.json',
        )
        return Response(
            json_util.dumps(documents, indent=2, ensure_ascii=False),
            content_type='application/json; charset=utf-8',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'},
        )
    except PyMongoError:
        return jsonify({'error': 'Unable to export vulnerability documents.'}), 503

import re
from collections import Counter
from datetime import datetime, timezone

from bson import json_util
from flask import Blueprint, Response, current_app, jsonify, render_template, request, session
from pymongo.errors import PyMongoError

from core.auth import login_required
from core.database import get_vulnerabilities_database
from reviews.query import (
    RELATED_CVE_LIMIT_PER_COLLECTION,
    RELATED_CVE_QUERY_BATCH_SIZE,
    _MappingFilterArgs,
    _build_filter,
    _collect_row_cve_ids,
    _collect_scored_review_rows,
    _extract_cve_ids,
    _first_summary_value,
    _is_review_view,
    _iter_collection_documents,
    _merged_review_rows,
    _paginated_cve_search_rows,
    _prepare_review_document,
    _query_review_slice,
    _review_sort_key,
    _review_view_names,
    _review_views,
    _serialize,
)
from reviews.repository import (
    MAX_EXPORT_SELECTIONS,
    canonical_selection_id,
    resolve_vulnerability_document,
)
from reviews.scoring import AUTO_SELECT_SCAN_LIMIT, rank_scored_selections


review_blueprint = Blueprint('review', __name__)


@review_blueprint.route('/reviews')
@login_required
def reviews():
    return render_template('reviews/index.html')


@review_blueprint.route('/reviews/<collection_name>')
@login_required
def review_collection(collection_name):
    try:
        if not _is_review_view(get_vulnerabilities_database(), collection_name):
            return render_template(
                'reviews/collection.html',
                collection_name=collection_name,
                initial_error='Review collection not found.',
            ), 404
    except PyMongoError:
        return render_template(
            'reviews/collection.html',
            collection_name=collection_name,
            initial_error='Unable to connect to the vulnerabilities database.',
        ), 503

    return render_template(
        'reviews/collection.html',
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
        'code': _first_summary_value(document, ('code', 'cve', 'cve_ids')),
        'title': _first_summary_value(document, ('title',)),
        'severity': _first_summary_value(document, ('severity', 'impacts')),
        'affected': _first_summary_value(document, ('affected', 'affected_products')),
        'is_self': collection_name == current_collection and selection_id == current_selection_id,
    }


def _related_cve_mongo_filter(cve_ids):
    prefixed = sorted({code.upper() for code in cve_ids})
    bare = sorted({code.removeprefix('CVE-') for code in prefixed})
    return {'$or': [
        {'cve_ids': {'$in': prefixed}},
        {'code': {'$in': bare}},
    ]}


def _related_candidates(database, views, cve_ids):
    all_codes = set(cve_ids)
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
                    'codes': set(_extract_cve_ids(document)),
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

    row_codes, all_codes = _collect_row_cve_ids(rows)
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


@review_blueprint.route('/api/reviews/auto-select', methods=['POST'])
@login_required
def auto_select_review_documents():
    data = request.get_json(silent=True) or {}
    try:
        count = int(data.get('count', 0))
    except (TypeError, ValueError):
        return jsonify({'error': 'count must be an integer.'}), 400
    if count < 1 or count > MAX_EXPORT_SELECTIONS:
        return jsonify({
            'error': f'Select between 1 and {MAX_EXPORT_SELECTIONS} vulnerability records.',
        }), 400

    filter_args = _MappingFilterArgs(data)
    try:
        mongo_filter = _build_filter(filter_args)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    try:
        database = get_vulnerabilities_database()
        views = _review_views(database)
        view_names = _selected_review_collections(filter_args, views)
        search = str(filter_args.get('search', '') or '').strip()
        rows = _collect_scored_review_rows(
            database,
            views,
            view_names,
            mongo_filter,
            search,
        )
        if len(rows) > AUTO_SELECT_SCAN_LIMIT:
            return jsonify({
                'error': (
                    f'Filter matched {len(rows)} documents, which exceeds the '
                    f'{AUTO_SELECT_SCAN_LIMIT}-document auto-select scan limit. '
                    'Narrow your filters and try again.'
                ),
            }), 400

        selected = rank_scored_selections(rows, count)
        summary = Counter(item['patch_priority'] for item in selected)
        return jsonify({
            'selections': [
                {
                    'collection': item['collection'],
                    'selection_id': item['selection_id'],
                    'selection_score': item['selection_score'],
                    'patch_priority': item['patch_priority'],
                    'cve_id': item['cve_id'],
                }
                for item in selected
            ],
            'summary': {
                priority: summary.get(priority, 0)
                for priority in ('Critical', 'High', 'Medium', 'Low')
            },
            'matched': len(rows),
            'selected': len(selected),
        })
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to query the vulnerabilities database.'}), 503
    except Exception:
        current_app.logger.exception('Unexpected review auto-select failure.')
        return jsonify({'error': 'Unable to auto-select review documents.'}), 500


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

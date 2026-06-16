import re
from datetime import datetime, timezone

from bson import json_util
from flask import Response, current_app, jsonify, render_template, request
from pymongo.errors import PyMongoError

from mongo import get_vulnerabilities_database
from preprocessing_priorities import (
    collection_base_priority,
    review_document_sort_key,
    scan_projection,
)
from review_data import (
    MAX_EXPORT_SELECTIONS,
    canonical_selection_id,
    resolve_vulnerability_document,
    review_views,
)
from . import review_blueprint
from .common import login_required


SUMMARY_FIELDS = ('code', 'cve', 'title', 'impacts', 'affected', 'affected_products')
FILTER_FIELDS = {
    'code': ('code', 'cve'),
    'title': ('title',),
    'impact': ('impacts',),
    'affected': ('affected', 'affected_products'),
}
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
    if search:
        clauses.append({'$or': [{field: _regex(search)} for field in SUMMARY_FIELDS]})

    for parameter, fields in FILTER_FIELDS.items():
        value = args.get(parameter, '').strip()
        if value:
            clauses.append({'$or': [{field: _regex(value)} for field in fields]})

    if not clauses:
        return {}
    if len(clauses) == 1:
        return clauses[0]
    return {'$and': clauses}


def _serialize(document):
    return json_util.loads(json_util.dumps(document))


def _source_projection(view):
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
    projection['scraped_at'] = 1
    projection['disclosure_date'] = 1
    return [first_stage, *pipeline[1:]]


def _search_projection(view, config):
    pipeline = _source_projection(view)
    first_stage = dict(pipeline[0])
    projection = dict(first_stage['$project'])
    for field, value in scan_projection(config).items():
        if field not in projection:
            projection[field] = value
    first_stage['$project'] = projection
    pipeline[0] = first_stage
    return pipeline


def _query_review_documents(database, view, mongo_filter, page, page_size):
    return _query_review_slice(
        database,
        view,
        mongo_filter,
        (page - 1) * page_size,
        page_size,
    )


def _query_review_matches(database, view, mongo_filter, config):
    source_name = view['options']['viewOn']
    pipeline = _search_projection(view, config)
    pipeline.extend([
        {'$match': mongo_filter},
        {
            '$facet': {
                'documents': [],
                'metadata': [{'$count': 'total'}],
            },
        },
    ])
    result = next(database[source_name].aggregate(pipeline), None) or {}
    total = (result.get('metadata') or [{}])[0].get('total', 0)
    documents = result.get('documents', [])
    return total, documents


def _query_review_slice(database, view, mongo_filter, skip, limit):
    source_name = view['options']['viewOn']
    pipeline = _source_projection(view)
    pipeline.extend([
        {'$match': mongo_filter},
        {'$sort': {'scraped_at': -1, '_id': -1}},
        {
            '$facet': {
                'documents': [
                    {'$skip': skip},
                    {'$limit': limit},
                ],
                'metadata': [{'$count': 'total'}],
            },
        },
    ])
    result = next(database[source_name].aggregate(pipeline), None) or {}
    total = (result.get('metadata') or [{}])[0].get('total', 0)
    documents = result.get('documents', [])
    return total, documents


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
        data = [
            {
                'name': name,
                'source': name[:-len(current_app.config['REVIEW_VIEW_SUFFIX'])],
                'count': database[name].count_documents({}),
            }
            for name in _review_view_names(database)
        ]
        return jsonify({'data': data})
    except PyMongoError:
        return jsonify({'error': 'Unable to connect to the vulnerabilities database.'}), 503


@review_blueprint.route('/api/reviews/search')
@login_required
def search_review_documents():
    collection_name = request.args.get('collection', '').strip()
    mongo_filter = _build_filter(request.args)
    if not mongo_filter and not collection_name:
        return jsonify({'error': 'Enter at least one filter.'}), 400

    try:
        database = get_vulnerabilities_database()
        views = _review_views(database)
        if collection_name:
            if collection_name not in views:
                return jsonify({'error': 'Review collection not found.'}), 400
            view_names = [collection_name]
        else:
            view_names = sorted(
                views,
                key=lambda name: collection_base_priority(views[name]['options']['viewOn'], current_app.config),
                reverse=True,
            )

        page = max(request.args.get('page', 1, type=int), 1)
        page_size = min(max(request.args.get('page_size', 25, type=int), 1), 100)
        global_skip = (page - 1) * page_size
        config = current_app.config
        total = 0
        merged = []

        for name in view_names:
            view_total, documents = _query_review_matches(
                database,
                views[name],
                mongo_filter,
                config,
            )
            total += view_total
            source_collection = views[name]['options']['viewOn']
            for document in documents:
                sort_key = review_document_sort_key(source_collection, document, config)
                merged.append({
                    'collection': name,
                    'selection_id': str(document.pop('_id')),
                    'document': _serialize(document),
                    '_sort': sort_key,
                })

        merged.sort(key=lambda item: item['_sort'], reverse=True)
        data = [
            {
                'collection': item['collection'],
                'selection_id': item['selection_id'],
                'document': item['document'],
            }
            for item in merged[global_skip:global_skip + page_size]
        ]

        return jsonify({
            'data': data,
            'page': page,
            'page_size': page_size,
            'total': total,
            'pages': max((total + page_size - 1) // page_size, 1),
        })
    except (PyMongoError, ValueError):
        return jsonify({'error': 'Unable to query the vulnerabilities database.'}), 503


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
        total, documents = _query_review_documents(
            database,
            view,
            mongo_filter,
            page,
            page_size,
        )

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
    except (PyMongoError, ValueError):
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

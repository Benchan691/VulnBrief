from bson import ObjectId
from bson.errors import InvalidId

from core.database import get_config


MAX_EXPORT_SELECTIONS = 500


def review_views(database):
    suffix = get_config()['REVIEW_VIEW_SUFFIX']
    views = list(database.list_collections(filter={'type': 'view'}))
    matched = {
        view['name']: view
        for view in views
        if view['name'].endswith(suffix)
    }
    return matched


def _lookup_queries(source_collection, selection_id):
    queries = [{'_id': selection_id}]
    try:
        queries.append({'_id': ObjectId(selection_id)})
    except (InvalidId, TypeError):
        pass
    if ':' in selection_id:
        _, _, suffix = selection_id.partition(':')
        if suffix:
            queries.extend([
                {'code': suffix},
                {'cve_code': suffix},
                {'cve_codes': suffix},
            ])
            if not selection_id.startswith(f'{source_collection}:'):
                queries.append({'_id': f'{source_collection}:{suffix}'})
    else:
        queries.extend([
            {'_id': f'{source_collection}:{selection_id}'},
            {'code': selection_id},
            {'cve_code': selection_id},
            {'cve_codes': selection_id},
        ])
        if source_collection == 'cve':
            queries.append({'cveMetadata.cveId': selection_id})
    unique = []
    seen = set()
    for query in queries:
        key = tuple(sorted((field, repr(value)) for field, value in query.items()))
        if key not in seen:
            seen.add(key)
            unique.append(query)
    return unique


def resolve_vulnerability_document(database, source_collection, selection_id, projection=None):
    if not isinstance(selection_id, str) or not selection_id.strip():
        return None
    collection = database[source_collection]
    for query in _lookup_queries(source_collection, selection_id):
        document = collection.find_one(query, projection)
        if document is not None:
            return document
    return None


def canonical_selection_id(document):
    return str(document['_id'])

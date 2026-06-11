from mongo import get_config


MAX_EXPORT_SELECTIONS = 500


def review_views(database):
    suffix = get_config()['REVIEW_VIEW_SUFFIX']
    views = database.list_collections(filter={'type': 'view'})
    return {
        view['name']: view
        for view in views
        if view['name'].endswith(suffix)
    }


def _lookup_queries(source_collection, selection_id):
    queries = [{'_id': selection_id}]
    if ':' in selection_id:
        _, _, suffix = selection_id.partition(':')
        if suffix:
            queries.extend([
                {'code': suffix},
                {'cve_code': suffix},
            ])
            if not selection_id.startswith(f'{source_collection}:'):
                queries.append({'_id': f'{source_collection}:{suffix}'})
    else:
        queries.extend([
            {'_id': f'{source_collection}:{selection_id}'},
            {'code': selection_id},
            {'cve_code': selection_id},
        ])
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

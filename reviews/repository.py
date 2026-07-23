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
    return [{'_id': selection_id}]


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

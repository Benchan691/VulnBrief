from core.database import get_config
from reviews.repository import review_views as live_review_views


def _review_suffix():
    try:
        return get_config().get('REVIEW_VIEW_SUFFIX') or '_review'
    except RuntimeError:
        return '_review'


def _collection_names(database):
    try:
        return set(database.list_collection_names())
    except AttributeError:
        try:
            return {
                item.get('name')
                for item in database.list_collections()
                if isinstance(item, dict)
            }
        except AttributeError:
            return set()


def source_collection_for_review(review_name, view):
    options = view.get('options') if isinstance(view, dict) else {}
    source = options.get('viewOn') if isinstance(options, dict) else ''
    if source:
        return source
    suffix = _review_suffix()
    if isinstance(review_name, str) and review_name.endswith(suffix):
        return review_name[:-len(suffix)]
    return ''


def _virtual_review_view(review_name, source_collection):
    return {
        'name': review_name,
        'options': {
            'viewOn': source_collection,
            'pipeline': [{'$project': {'_id': 1}}],
        },
    }


def subscription_review_views(database):
    """Return live review views plus fallbacks for physical source collections."""
    views = dict(live_review_views(database))
    suffix = _review_suffix()
    collection_names = _collection_names(database)
    live_sources = {
        source_collection_for_review(name, view)
        for name, view in views.items()
    }
    for source in sorted(collection_names):
        if (
            not source
            or source.endswith(suffix)
            or source.startswith('system.')
            or '__backup_' in source
            or source in live_sources
        ):
            continue
        review_name = f'{source}{suffix}'
        if review_name not in views:
            views[review_name] = _virtual_review_view(review_name, source)
    return views

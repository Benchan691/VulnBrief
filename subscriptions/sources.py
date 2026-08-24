from reviews.repository import review_views as live_review_views


ZIMBRA_SOURCE = 'zimbra'
ZIMBRA_REVIEW = 'zimbra_review'


def _collection_names(database):
    try:
        return set(database.list_collection_names())
    except AttributeError:
        return {
            item.get('name')
            for item in database.list_collections()
            if isinstance(item, dict)
        }


def subscription_review_views(database):
    """Return review sources available to subscriptions, including Zimbra."""
    views = dict(live_review_views(database))
    if ZIMBRA_REVIEW not in views and ZIMBRA_SOURCE in _collection_names(database):
        views[ZIMBRA_REVIEW] = {
            'name': ZIMBRA_REVIEW,
            'options': {
                'viewOn': ZIMBRA_SOURCE,
                'pipeline': [{'$project': {'_id': 1}}],
            },
        }
    return views

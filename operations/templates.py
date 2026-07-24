from datetime import datetime, timezone

from reviews.repository import review_views


TIMESTAMP_FIELDS = ('observed_at', 'published_at', 'scraped_at')


def _source_timestamp(document):
    for field in TIMESTAMP_FIELDS:
        value = document.get(field)
        if value not in (None, ''):
            return value
    return None


def _timestamp_value(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
        except ValueError:
            return float('-inf')
    return float('-inf')


def _timestamp_text(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value or '')


def _document_sort_key(document):
    timestamp = _source_timestamp(document)
    return (
        timestamp is not None,
        _timestamp_value(timestamp),
        str(document.get('_id') or ''),
    )


def latest_newsletter_templates(database):
    """Return one newest source record for every active review source."""
    sources = {}
    for review_collection, view in review_views(database).items():
        source_collection = (view.get('options') or {}).get('viewOn')
        if source_collection:
            sources.setdefault(source_collection, []).append(review_collection)

    rows = []
    for source_collection in sorted(sources):
        latest = None
        for document in database[source_collection].find({}):
            if latest is None or _document_sort_key(document) > _document_sort_key(latest):
                latest = document
        timestamp = _source_timestamp(latest) if latest is not None else None
        rows.append({
            'source_collection': source_collection,
            'review_collections': sorted(sources[source_collection]),
            'selection_id': str(latest['_id']) if latest is not None else '',
            'source_timestamp': _timestamp_text(timestamp),
        })
    return rows

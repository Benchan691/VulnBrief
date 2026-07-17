import hashlib

from newsletters.normalizer import normalize_newsletter
from reviews.repository import resolve_vulnerability_document
from subscriptions.profiles import validate_filters
from subscriptions.query import query_profile_matches


def _record_id(source_collection, selection_id):
    value = f'{source_collection}\0{selection_id}'.encode('utf-8')
    return hashlib.sha256(value).hexdigest()


DEFAULT_FEED_LIMIT = 100


def _matches_keyword(newsletter, source_collection, keyword):
    terms = str(keyword or '').casefold().split()
    if not terms:
        return True
    values = [
        source_collection,
        newsletter['title'],
        newsletter['overview'],
        *newsletter['severity'],
        *newsletter['impacts'],
        *newsletter['affected'],
        *newsletter['recommendations'],
        *newsletter['references'],
        *newsletter['related_links'],
        *newsletter['cves'],
    ]
    text = ' '.join(str(value) for value in values).casefold()
    return all(term in text for term in terms)


def filter_newsletter_feed(database, email, filters, limit=DEFAULT_FEED_LIMIT, offset=0):
    keyword = (filters or {}).get('keyword', '')
    validated = validate_filters(database, {
        key: value for key, value in (filters or {}).items() if key != 'keyword'
    })
    matches = query_profile_matches(
        database,
        {'filters': validated},
        limit=None,
        include_documents=True,
    )
    items = []
    for match in matches:
        source_collection = match['source_collection']
        selection_id = match['selection_id']
        document = match.get('document')
        if document is None:
            document = resolve_vulnerability_document(database, source_collection, selection_id)
        if document is None:
            continue
        normalized = normalize_newsletter(document, source_collection)
        if not _matches_keyword(normalized, source_collection, keyword):
            continue
        generated_at = document.get('scraped_at') or document.get('disclosure_date') or ''
        items.append({
            'id': _record_id(source_collection, selection_id),
            'source_collection': source_collection,
            'selection_id': selection_id,
            'title': normalized['title'],
            'template_key': normalized['template_key'],
            'generated_at': generated_at,
        })
    items.sort(key=lambda item: (item['generated_at'], item['id']), reverse=True)
    total = len(items)
    if offset:
        items = items[offset:]
    if limit is not None:
        items = items[:limit]
    return items, total

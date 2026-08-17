from datetime import datetime, timezone

from newsletters.normalizer import normalize_newsletter
from reviews.repository import review_views


TIMESTAMP_FIELDS = ('observed_at', 'published_at', 'scraped_at')
NEWSLETTER_TEMPLATE_CONFIG_ID = 'newsletter_default'

TEMPLATE_FIELD_CATALOG = (
    {'id': 'title', 'label': 'Title', 'description': 'The advisory or vulnerability title.'},
    {'id': 'collection', 'label': 'Source collection', 'description': 'The collection that supplied this record.'},
    {'id': 'overview', 'label': 'Overview', 'description': 'The source summary or description.'},
    {'id': 'table', 'label': 'Source table', 'description': 'A structured table supplied by the source.'},
    {'id': 'severity', 'label': 'Severity', 'description': 'Severity or risk rating.'},
    {'id': 'cvss', 'label': 'CVSS', 'description': 'CVSS score or vector supplied by the source.'},
    {'id': 'impacts', 'label': 'Impacts', 'description': 'The effects or consequences described by the source.'},
    {'id': 'affected', 'label': 'Affected systems', 'description': 'Products, systems, or versions that are affected.'},
    {'id': 'cves', 'label': 'CVE identifiers', 'description': 'CVE identifiers found in the record.'},
    {'id': 'recommendations', 'label': 'Recommendations', 'description': 'Fixes, patches, or mitigation guidance.'},
    {'id': 'references', 'label': 'References', 'description': 'Reference URLs from the source.'},
    {'id': 'related_links', 'label': 'Related links', 'description': 'Additional source or related URLs.'},
)
TEMPLATE_FIELD_IDS = tuple(field['id'] for field in TEMPLATE_FIELD_CATALOG)
DEFAULT_FIELD_ORDER = [field_id for field_id in TEMPLATE_FIELD_IDS if field_id != 'cvss']
DEFAULT_TEMPLATE_COMMON = {
    'subject': 'Security newsletter: {{title}}',
    'extra': '',
    'footer': '',
}


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


def _clean_common(common):
    common = common if isinstance(common, dict) else {}
    return {
        key: str(common.get(key) or '').strip()
        for key in ('subject', 'extra', 'footer')
    }


def _clean_fields(fields):
    if not isinstance(fields, list):
        return list(DEFAULT_FIELD_ORDER)
    cleaned = []
    for field in fields:
        value = str(field or '').strip()
        if value in TEMPLATE_FIELD_IDS and value not in cleaned:
            cleaned.append(value)
    return cleaned


def normalize_template_config(document=None):
    document = document if isinstance(document, dict) else {}
    sources = document.get('sources') if isinstance(document.get('sources'), dict) else {}
    common = dict(DEFAULT_TEMPLATE_COMMON)
    if isinstance(document.get('common'), dict):
        common.update(_clean_common(document['common']))
    return {
        'common': common,
        'sources': {
            str(source): {'fields': _clean_fields(value.get('fields'))}
            for source, value in sources.items()
            if isinstance(value, dict)
        },
    }


def get_newsletter_template_config(database):
    stored = database['newsletter_template_config'].find_one({'_id': NEWSLETTER_TEMPLATE_CONFIG_ID})
    return normalize_template_config(stored)


def save_newsletter_template_config(database, payload):
    payload = payload if isinstance(payload, dict) else {}
    sources = payload.get('sources') if isinstance(payload.get('sources'), dict) else {}
    config = normalize_template_config({
        'common': payload.get('common'),
        'sources': {
            str(source): {'fields': value.get('fields')}
            for source, value in sources.items()
            if isinstance(value, dict)
        },
    })
    database['newsletter_template_config'].update_one(
        {'_id': NEWSLETTER_TEMPLATE_CONFIG_ID},
        {'$set': {
            'common': config['common'],
            'sources': config['sources'],
            'updated_at': datetime.now(timezone.utc),
        }},
        upsert=True,
    )
    return config


def _field_available(newsletter, field_id):
    if field_id in {'title', 'collection', 'overview'}:
        return bool(newsletter.get(field_id))
    if field_id == 'table':
        return bool(newsletter.get('table'))
    if field_id == 'severity':
        return bool(newsletter.get('show_severity') and newsletter.get('severity'))
    if field_id == 'cvss':
        return bool(newsletter.get('cvss'))
    if field_id == 'impacts':
        return bool(newsletter.get('show_impacts') and newsletter.get('impacts'))
    if field_id == 'affected':
        return bool(newsletter.get('show_affected') and (
            newsletter.get('affected') or newsletter.get('affected_table')
        ))
    if field_id == 'recommendations':
        return bool(
            newsletter.get('show_recommendations', True) and newsletter.get('recommendations')
        )
    return bool(newsletter.get(field_id))


def newsletter_editor_rows(vulnerability_database, web_database):
    config = get_newsletter_template_config(web_database)
    rows = []
    for row in latest_newsletter_templates(vulnerability_database):
        source = row['source_collection']
        latest = None
        if row['selection_id']:
            latest = vulnerability_database[source].find_one({'_id': row['selection_id']})
        newsletter = normalize_newsletter(latest or {}, source)
        source_config = config['sources'].get(source) or {'fields': list(DEFAULT_FIELD_ORDER)}
        fields = _clean_fields(source_config.get('fields'))
        catalog = []
        for field in TEMPLATE_FIELD_CATALOG:
            available = _field_available(newsletter, field['id'])
            if field['id'] == 'cvss' and not available and field['id'] not in fields:
                continue
            catalog.append({**field, 'available': available})
        rows.append({
            **row,
            'fields': fields,
            'field_catalog': catalog,
        })
    return {
        'common': config['common'],
        'sources': rows,
        'field_catalog': list(TEMPLATE_FIELD_CATALOG),
    }

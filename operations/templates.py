from datetime import datetime, timezone

from newsletters.detail_fields import (
    discover_detail_fields,
    extract_detail_path,
    is_detail_path,
)
from newsletters.normalizer import normalize_newsletter
from reviews.repository import review_views


TIMESTAMP_FIELDS = ('observed_at', 'published_at', 'scraped_at')
NEWSLETTER_TEMPLATE_CONFIG_ID = 'newsletter_default'

TEMPLATE_FIELD_CATALOG = (
    {'id': 'title', 'label': 'Title', 'group': 'Built-in fields', 'type': 'text', 'builtin': True, 'description': 'The advisory or vulnerability title.'},
    {'id': 'collection', 'label': 'Source collection', 'group': 'Built-in fields', 'type': 'text', 'builtin': True, 'description': 'The collection that supplied this record.'},
    {'id': 'overview', 'label': 'Overview', 'group': 'Built-in fields', 'type': 'text', 'builtin': True, 'description': 'The source summary or description.'},
    {'id': 'table', 'label': 'Source table', 'group': 'Built-in fields', 'type': 'table', 'builtin': True, 'description': 'A structured table supplied by the source.'},
    {'id': 'severity', 'label': 'Severity', 'group': 'Built-in fields', 'type': 'list', 'builtin': True, 'description': 'Severity or risk rating.'},
    {'id': 'impacts', 'label': 'Impacts', 'group': 'Built-in fields', 'type': 'list', 'builtin': True, 'description': 'The effects or consequences described by the source.'},
    {'id': 'affected', 'label': 'Affected systems', 'group': 'Built-in fields', 'type': 'list', 'builtin': True, 'description': 'Products, systems, or versions that are affected.'},
    {'id': 'cves', 'label': 'CVE identifiers', 'group': 'Built-in fields', 'type': 'list', 'builtin': True, 'description': 'CVE identifiers found in the record.'},
    {'id': 'recommendations', 'label': 'Recommendations', 'group': 'Built-in fields', 'type': 'list', 'builtin': True, 'description': 'Fixes, patches, or mitigation guidance.'},
    {'id': 'references', 'label': 'References', 'group': 'Built-in fields', 'type': 'list', 'builtin': True, 'description': 'Reference URLs from the source.'},
    {'id': 'related_links', 'label': 'Related links', 'group': 'Built-in fields', 'type': 'list', 'builtin': True, 'description': 'Additional source or related URLs.'},
)
TEMPLATE_FIELD_IDS = tuple(field['id'] for field in TEMPLATE_FIELD_CATALOG)
DEFAULT_FIELD_ORDER = list(TEMPLATE_FIELD_IDS)
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
        try:
            documents = database[source_collection].find({}, {
                '_id': 1,
                'observed_at': 1,
                'published_at': 1,
                'scraped_at': 1,
            })
        except TypeError:
            documents = database[source_collection].find({})
        for document in documents:
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
        if (value in TEMPLATE_FIELD_IDS or is_detail_path(value)) and value not in cleaned:
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


def save_newsletter_template_config(database, payload, vulnerability_database=None):
    payload = payload if isinstance(payload, dict) else {}
    sources = payload.get('sources') if isinstance(payload.get('sources'), dict) else {}
    stored = database['newsletter_template_config'].find_one({'_id': NEWSLETTER_TEMPLATE_CONFIG_ID}) or {}
    previous = normalize_template_config(stored).get('sources') or {}
    known_by_source = {}
    if vulnerability_database is not None:
        source_names = sorted({
            (view.get('options') or {}).get('viewOn')
            for view in review_views(vulnerability_database).values()
            if (view.get('options') or {}).get('viewOn')
        })
        known_by_source = {
            source: {field['id'] for field in discover_detail_fields(vulnerability_database, source)}
            for source in source_names
        }
    for source, value in sources.items():
        if not isinstance(value, dict):
            continue
        for field in value.get('fields') or []:
            field = str(field or '').strip()
            if is_detail_path(field) and vulnerability_database is not None:
                if field not in known_by_source.get(source, set()) and field not in {
                    str(item).strip() for item in (previous.get(source) or {}).get('fields') or []
                }:
                    raise ValueError(f'Unknown details field for {source}: {field}')
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
    if field_id == 'impacts':
        return bool(newsletter.get('show_impacts') and newsletter.get('impacts'))
    if field_id == 'affected':
        return bool(newsletter.get('show_affected') and (
            newsletter.get('affected') or newsletter.get('affected_table')
        ))
    return bool(newsletter.get(field_id))


def _detail_field_available(document, field):
    value = extract_detail_path((document or {}).get('details'), field['path'])
    return value not in (None, '', [], {})


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
        detail_catalog = discover_detail_fields(vulnerability_database, source)
        catalog = [
            {**field, 'available': _field_available(newsletter, field['id'])}
            for field in TEMPLATE_FIELD_CATALOG
        ]
        catalog.extend([
            {**field, 'available': _detail_field_available(latest, field)}
            for field in detail_catalog
        ])
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

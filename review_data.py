from bson import ObjectId
from bson.errors import InvalidId

from mongo import get_config

MAX_EXPORT_SELECTIONS = 500


def _first_non_empty_str(*values):
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ''


def _cna_descriptions(cna):
    if not isinstance(cna, dict):
        return ''
    descriptions = cna.get('descriptions') or []
    parts = []
    for item in descriptions:
        if isinstance(item, dict):
            text = str(item.get('value') or '').strip()
            if text:
                parts.append(text)
    return '\n'.join(parts)


def _cna_severity(cna):
    if not isinstance(cna, dict):
        return ''
    for metric in cna.get('metrics') or []:
        if not isinstance(metric, dict):
            continue
        for key in ('cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0'):
            data = metric.get(key)
            if isinstance(data, dict):
                severity = _first_non_empty_str(data.get('baseSeverity'))
                if severity:
                    return severity
    return ''


def _cna_affected(cna):
    if not isinstance(cna, dict):
        return []
    affected = []
    for item in cna.get('affected') or []:
        if not isinstance(item, dict):
            continue
        vendor = str(item.get('vendor') or '').strip()
        product = str(item.get('product') or '').strip()
        label = ' '.join(part for part in (vendor, product) if part).strip()
        if label:
            affected.append(label)
    return affected


def _cna_vendor_product(cna):
    if not isinstance(cna, dict):
        return '', ''
    for item in cna.get('affected') or []:
        if not isinstance(item, dict):
            continue
        vendor = str(item.get('vendor') or '').strip()
        product = str(item.get('product') or '').strip()
        if vendor or product:
            return vendor, product
    return '', ''


def _cna_references(cna):
    if not isinstance(cna, dict):
        return []
    links = []
    for item in cna.get('references') or []:
        if isinstance(item, dict):
            url = str(item.get('url') or '').strip()
            if url:
                links.append(url)
    return links


def normalize_cve_record_document(document):
    if not isinstance(document, dict):
        return document

    cna = (document.get('containers') or {}).get('cna') or {}
    metadata = document.get('cveMetadata') or {}
    if not cna and not metadata:
        return document

    cve_id = _first_non_empty_str(
        document.get('code'),
        document.get('cve'),
        document.get('cve_code'),
        metadata.get('cveId'),
    )
    advisory_title = _first_non_empty_str(cna.get('title'), document.get('title'))
    severity = _first_non_empty_str(
        _cna_severity(cna),
        document.get('severity'),
        document.get('impacts'),
        document.get('status'),
    )
    vendor, product = _cna_vendor_product(cna)
    normalized = dict(document)
    normalized['code'] = cve_id
    normalized['cve'] = cve_id
    normalized['title'] = cve_id or advisory_title
    normalized['advisory_title'] = advisory_title
    normalized['description'] = _first_non_empty_str(
        document.get('description'),
        _cna_descriptions(cna),
        advisory_title,
    )
    normalized['severity'] = severity
    normalized['impacts'] = severity
    existing_affected = document.get('affected') or document.get('affected_products') or []
    if isinstance(existing_affected, list) and existing_affected:
        normalized['affected'] = existing_affected
    else:
        normalized['affected'] = _cna_affected(cna)
    existing_links = document.get('related_link') or document.get('references') or []
    if isinstance(existing_links, list) and existing_links:
        normalized['related_link'] = existing_links
    else:
        normalized['related_link'] = _cna_references(cna)
    if not normalized.get('disclosure_date'):
        normalized['disclosure_date'] = metadata.get('datePublished') or metadata.get('dateUpdated')

    classification = document.get('classification') if isinstance(document.get('classification'), dict) else {}
    if classification.get('status') == 'unclassified':
        normalized['classification'] = classification
    elif _first_non_empty_str(
        classification.get('vendor'),
        classification.get('best_vendor'),
        classification.get('product'),
        classification.get('best_product'),
    ):
        normalized['classification'] = classification
        normalized['vendor'] = _first_non_empty_str(
            classification.get('vendor'),
            classification.get('best_vendor'),
        )
        normalized['product'] = _first_non_empty_str(
            classification.get('product'),
            classification.get('best_product'),
        )
    elif vendor or product:
        normalized['vendor'] = vendor
        normalized['product'] = product
        normalized['classification'] = {
            'vendor': vendor,
            'product': product,
            'best_vendor': vendor,
            'best_product': product,
        }
    return normalized


def is_cve_record_document(document):
    return isinstance(document, dict) and (
        isinstance(document.get('cveMetadata'), dict)
        or isinstance((document.get('containers') or {}).get('cna'), dict)
    )


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

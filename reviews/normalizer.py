import re

_CWE_LABEL_PATTERN = re.compile(r'^CWE-\d+\b', re.IGNORECASE)
CVE_ID_PATTERN = re.compile(r'\b(?:CVE-)?(\d{4}-\d{4,})\b', re.IGNORECASE)


def normalize_cve_id(value):
    if value is None:
        return ''
    if isinstance(value, list):
        for item in value:
            normalized = normalize_cve_id(item)
            if normalized:
                return normalized
        return ''
    text = _flatten_text(value) if isinstance(value, dict) else str(value).strip()
    match = CVE_ID_PATTERN.search(text)
    if not match:
        return ''
    return f'CVE-{match.group(1).upper()}'


def extract_document_cve_id(document):
    if not isinstance(document, dict):
        return ''
    metadata = document.get('cveMetadata') if isinstance(document.get('cveMetadata'), dict) else {}
    return normalize_cve_id([
        document.get('code'),
        document.get('_id'),
        document.get('title'),
        metadata.get('cveId'),
        document.get('cve_id'),
        document.get('cve'),
        document.get('cve_code'),
        document.get('cve_codes'),
    ])


def _first_non_empty_str(*values):
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ''


def _flatten_text(value):
    if value is None:
        return ''
    if isinstance(value, list):
        return ' '.join(_flatten_text(item) for item in value)
    if isinstance(value, dict):
        return ' '.join(_flatten_text(item) for item in value.values())
    return str(value).strip()


def _first_nested_text(document, key_names):
    key_names = set(key_names)
    stack = [document]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, value in current.items():
                if key in key_names:
                    text = _flatten_text(value).strip()
                    if text:
                        return text
                if isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(current, list):
            stack.extend(current)
    return ''


def _cve_details_block(document):
    details = document.get('details') if isinstance(document.get('details'), dict) else {}
    cve = details.get('cve') if isinstance(details.get('cve'), dict) else {}
    return cve


def _descriptions_list_values(container):
    if not isinstance(container, dict):
        return ''
    parts = []
    for item in container.get('descriptions') or []:
        if isinstance(item, dict):
            text = str(item.get('value') or '').strip()
            if text:
                parts.append(text)
    return '\n'.join(parts)


def _is_cwe_label(text):
    return bool(_CWE_LABEL_PATTERN.match(str(text or '').strip()))


def _affected_vendor_product(items):
    for item in items or []:
        if not isinstance(item, dict):
            continue
        vendor = str(item.get('vendor') or '').strip()
        product = str(item.get('product') or '').strip()
        if vendor or product:
            return vendor, product
    return '', ''


def extract_document_description(document):
    if not isinstance(document, dict):
        return ''
    cna = (document.get('containers') or {}).get('cna') or {}
    cve_details = _cve_details_block(document)
    structured = _first_non_empty_str(
        _cna_descriptions(cna),
        _descriptions_list_values(cve_details),
        cve_details.get('description'),
    )
    if structured:
        # #region agent log
        try:
            import json as _json, urllib.request as _url
            _payload = _json.dumps({'sessionId': '5a3615', 'hypothesisId': 'A', 'location': 'normalizer.py:extract_document_description', 'message': 'structured description found', 'data': {'source': 'cna_or_cve_details', 'len': len(structured), 'preview': structured[:80]}, 'timestamp': __import__('time').time() * 1000}).encode()
            _req = _url.Request('http://host.docker.internal:7930/ingest/963a9c32-06bb-450a-a312-2a970a022ece', data=_payload, headers={'Content-Type': 'application/json', 'X-Debug-Session-Id': '5a3615'}, method='POST')
            _url.urlopen(_req, timeout=0.5)
        except Exception:
            pass
        # #endregion
        return structured
    details = document.get('details') if isinstance(document.get('details'), dict) else {}
    details_descriptions = _descriptions_list_values(details)
    nested_summary = _first_nested_text(details, ('summary', 'overview', 'vulDesc'))
    nested_description = _first_nested_text(details, ('description',))
    # #region agent log
    if details_descriptions or nested_description:
        try:
            import json as _json, urllib.request as _url
            _payload = _json.dumps({'sessionId': '5a3615', 'hypothesisId': 'A,B', 'location': 'normalizer.py:extract_document_description', 'message': 'missed nested description candidates', 'data': {'details_keys': list(details.keys())[:20], 'has_details_descriptions_list': bool(details_descriptions), 'details_descriptions_preview': (details_descriptions or '')[:80], 'has_nested_summary': bool(nested_summary), 'has_nested_description': bool(nested_description), 'nested_description_preview': (nested_description or '')[:80], 'top_description': bool(_first_non_empty_str(document.get('description'))), 'top_summary': bool(_first_non_empty_str(document.get('summary'))), 'will_return_empty': not bool(_first_non_empty_str(document.get('summary'), document.get('description'), document.get('overview'), nested_summary))}, 'timestamp': __import__('time').time() * 1000}).encode()
            _req = _url.Request('http://host.docker.internal:7930/ingest/963a9c32-06bb-450a-a312-2a970a022ece', data=_payload, headers={'Content-Type': 'application/json', 'X-Debug-Session-Id': '5a3615'}, method='POST')
            _url.urlopen(_req, timeout=0.5)
        except Exception:
            pass
    # #endregion
    for candidate in (
        document.get('summary'),
        document.get('description'),
        document.get('overview'),
        nested_summary,
    ):
        text = _first_non_empty_str(candidate)
        if text and not _is_cwe_label(text):
            return text
    return _first_non_empty_str(
        document.get('summary'),
        document.get('description'),
        document.get('overview'),
    )


def extract_document_vendor_product(document):
    if not isinstance(document, dict):
        return '', ''
    cna = (document.get('containers') or {}).get('cna') or {}
    cve_details = _cve_details_block(document)
    details = document.get('details') if isinstance(document.get('details'), dict) else {}

    for vendor, product in (
        _affected_vendor_product(cve_details.get('affected')),
        _cna_vendor_product(cna),
    ):
        if vendor or product:
            return vendor, product

    return (
        _first_non_empty_str(
            document.get('vendor'),
            _first_nested_text(details, ('vendor', 'vendor_name', 'manufacturer')),
        ),
        _first_non_empty_str(
            document.get('product'),
            _first_nested_text(details, ('product', 'product_name', 'packageName')),
        ),
    )


def promote_cve_display_fields(document):
    if not isinstance(document, dict):
        return document
    document = dict(document)
    description = extract_document_description(document)
    existing_description = _first_non_empty_str(document.get('description'))
    existing_summary = _first_non_empty_str(document.get('summary'))
    if description:
        if not existing_description or (_is_cwe_label(existing_description) and description != existing_description):
            document['description'] = description
        if not existing_summary or (_is_cwe_label(existing_summary) and description != existing_summary):
            document['summary'] = description
    vendor, product = extract_document_vendor_product(document)
    if vendor and not _first_non_empty_str(document.get('vendor')):
        document['vendor'] = vendor
    if product and not _first_non_empty_str(document.get('product')):
        document['product'] = product
    return document


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
        return promote_cve_display_fields(document)

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
        _cna_descriptions(cna),
        _descriptions_list_values(_cve_details_block(document)),
        document.get('summary'),
        document.get('description'),
        _first_nested_text(document.get('details') or {}, ('summary', 'overview', 'vulDesc')),
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

    nested_vendor, nested_product = extract_document_vendor_product(document)
    if vendor or product:
        normalized['vendor'] = vendor
        normalized['product'] = product
    elif nested_vendor or nested_product:
        if nested_vendor:
            normalized['vendor'] = nested_vendor
        if nested_product:
            normalized['product'] = nested_product
    return promote_cve_display_fields(normalized)


def is_cve_record_document(document):
    return isinstance(document, dict) and (
        isinstance(document.get('cveMetadata'), dict)
        or isinstance((document.get('containers') or {}).get('cna'), dict)
    )


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
    return normalize_cve_id([
        document.get('code'),
        document.get('_id'),
        document.get('title'),
        document.get('cve'),
        document.get('cve_ids'),
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
    return details


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
    cve_details = _cve_details_block(document)
    details = document.get('details') if isinstance(document.get('details'), dict) else {}
    details_description = details.get('description')
    if isinstance(details_description, (dict, list)):
        details_description = ''
    structured = _first_non_empty_str(
        _descriptions_list_values(cve_details),
        cve_details.get('description'),
        _descriptions_list_values(details),
        details_description if not _is_cwe_label(details_description) else '',
    )
    if structured:
        return structured
    nested_summary = _first_nested_text(details, ('summary', 'overview', 'vulDesc'))
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
    cve_details = _cve_details_block(document)
    details = document.get('details') if isinstance(document.get('details'), dict) else {}

    vendor, product = _affected_vendor_product(cve_details.get('affected'))
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


def normalize_cve_record_document(document):
    if not isinstance(document, dict):
        return document
    return promote_cve_display_fields(document)


def is_cve_record_document(document):
    return isinstance(document, dict) and str(document.get('_id') or '').startswith('cve:')

import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse

import bleach
from bson import json_util
from flask import render_template
from markupsafe import Markup

from mongo import get_vulnerabilities_database, get_web_database
from review_data import resolve_vulnerability_document
from subscription_data import normalize_subscription, query_profile_matches, validate_filters


ALLOWED_TAGS = {
    'a', 'b', 'blockquote', 'br', 'code', 'div', 'em', 'h2', 'h3', 'li', 'ol',
    'p', 'pre', 'span', 'strong', 'table', 'tbody', 'td', 'th', 'thead', 'tr', 'ul',
}
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'rel', 'target'],
    'td': ['colspan', 'rowspan'],
    'th': ['colspan', 'rowspan'],
}
SOURCE_TEMPLATE_KEYS = {
    'avd', 'cisco', 'cnnvd', 'cnvd', 'cve', 'github_advisory', 'govcert',
    'hikvision', 'hkcert', 'huawei_sa', 'infosec', 'juniper', 'paloalto',
    'qianxin', 'ransomwarelive', 'splunk', 'zeroday',
}
CHINESE_TEMPLATE_KEYS = {'cnvd', 'cnnvd', 'huawei_sa', 'qianxin'}
ENGLISH_LABELS = {
    'greeting': 'Dear Valued Customer,',
    'overview': 'Overview:',
    'severity': 'Severity:',
    'impacts': 'Impacts:',
    'affected': 'Affected system:',
    'cves': 'CVEs:',
    'recommendations': 'Recommendations:',
    'references': 'References:',
    'related_links': 'Related Links:',
    'not_specified': 'Not specified',
    'default_recommendation': 'Refer to the vendor guidance and apply available fixes.',
    'footer': 'Should you have any queries, please contact the Security Operation Centre. Thank you.',
}
CHINESE_LABELS = {
    'greeting': '尊敬的客户：',
    'overview': '概述：',
    'severity': '严重程度：',
    'impacts': '影响：',
    'affected': '受影响系统：',
    'cves': 'CVE：',
    'recommendations': '建议：',
    'references': '参考资料：',
    'related_links': '相关链接：',
    'not_specified': '未说明',
    'default_recommendation': '请参考供应商指南并应用可用修复。',
    'footer': '如有任何疑问，请联系安全运营中心。谢谢。',
}


def get_newsletter_collection():
    return get_web_database()['generated_newsletters']


def _details(document, source_collection=None):
    details = document.get('details') or {}
    if isinstance(details, dict) and source_collection:
        value = details.get(source_collection)
        if isinstance(value, dict):
            return value
    if isinstance(details, dict) and len(details) == 1:
        value = next(iter(details.values()))
        return value if isinstance(value, dict) else details
    return details if isinstance(details, dict) else {}


def _values(value):
    if value in (None, '', [], {}):
        return []
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_values(item))
        return result
    if isinstance(value, dict):
        result = []
        for item in value.values():
            result.extend(_values(item))
        return result
    return [str(value)]


def _first(details, document, *fields):
    for source in (details, document):
        for field in fields:
            values = _values(source.get(field))
            if values:
                return values[0]
    return ''


def _all(details, document, *fields):
    result = []
    seen = set()
    for source in (details, document):
        for field in fields:
            for value in _values(source.get(field)):
                key = value.casefold()
                if key not in seen:
                    seen.add(key)
                    result.append(value)
    return result


def _safe_html(value):
    return Markup(bleach.clean(
        str(value or ''),
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols={'http', 'https', 'mailto'},
        strip=True,
    ))


def _links(values):
    links = []
    seen = set()
    for value in _values(values):
        for part in str(value).replace('\r', '\n').split():
            candidate = part.strip(' \n\r\t,;()[]<>')
            parsed = urlparse(candidate)
            if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
                continue
            if candidate not in seen:
                seen.add(candidate)
                links.append(candidate)
    return links


def template_key_for_source(source_collection):
    return source_collection if source_collection in SOURCE_TEMPLATE_KEYS else 'generic'


def _hkcert_table(details):
    raw = details.get('table')
    if isinstance(raw, list) and raw and all(isinstance(row, dict) for row in raw):
        headers = list(dict.fromkeys(key for row in raw for key in row))
        if not headers:
            return None
        return {
            'headers': headers,
            'rows': [[str(row.get(header, '')) for header in headers] for row in raw],
        }
    return None


def _raw_table(details):
    raw_tables = details.get('raw_tables')
    if not isinstance(raw_tables, list):
        return None
    for grid in raw_tables:
        if not isinstance(grid, list) or len(grid) < 2:
            continue
        rows = [
            [str(cell or '') for cell in row]
            for row in grid
            if isinstance(row, list)
        ]
        if len(rows) < 2:
            continue
        width = max(len(row) for row in rows)
        headers = []
        used = set()
        for index, value in enumerate(rows[0] + [''] * (width - len(rows[0])), start=1):
            header = value.strip() or f'Column {index}'
            candidate = header
            suffix = 2
            while candidate.casefold() in used:
                candidate = f'{header} {suffix}'
                suffix += 1
            used.add(candidate.casefold())
            headers.append(candidate)
        return {
            'headers': headers,
            'rows': [row + [''] * (width - len(row)) for row in rows[1:]],
        }
    return None


def _parts(*values):
    return ' '.join(str(value).strip() for value in values if value not in (None, '', [], {}))


def _severity_label(value):
    text = str(value or '').strip()
    mapping = {
        '1': 'Critical', '超危': 'Critical', '严重': 'Critical',
        '2': 'High', '高危': 'High', '高': 'High',
        '3': 'Medium', '中危': 'Medium', '中': 'Medium',
        '4': 'Low', '低危': 'Low', '低': 'Low',
    }
    if text in mapping:
        return mapping[text]
    lowered = text.casefold()
    for label in ('Critical', 'High', 'Medium', 'Low'):
        if lowered.startswith(label.casefold()):
            return label
    return text


def _dict_lines(values, fields):
    lines = []
    if not isinstance(values, list):
        return lines
    for item in values:
        if not isinstance(item, dict):
            continue
        line = _parts(*(item.get(field) for field in fields))
        if line and line not in lines:
            lines.append(line)
    return lines


def _nested_values(values, field):
    result = []
    if not isinstance(values, list):
        return result
    for item in values:
        if isinstance(item, dict):
            result.extend(_values(item.get(field)))
    return result


def _path(value, *fields):
    for field in fields:
        if not isinstance(value, dict):
            return None
        value = value.get(field)
    return value


def _cnvd_title(document, details):
    raw_title = _path(details, 'raw_fields', '厂商补丁')
    if isinstance(raw_title, str) and raw_title.endswith('的补丁'):
        raw_title = raw_title[:-3].strip()
    detail_title = details.get('title')
    document_title = document.get('title')
    for value in (raw_title, document_title, detail_title):
        text = str(value or '').strip()
        if text and text != '相关漏洞':
            return text
    return ''


def _qianxin_affected(details):
    vulnerability = _path(details, 'description', 'vulnerability_information') or {}
    values = []
    product = _parts(vulnerability.get('vendor'), vulnerability.get('product'))
    if product:
        values.append(product)
    values.extend(_values(vulnerability.get('affected_versions')))
    other = vulnerability.get('other_affected_components')
    if str(other or '').strip() not in {'', '无'}:
        values.extend(_values(other))
    return values


def _github_affected(details):
    values = []
    for item in details.get('vulnerabilities') or []:
        if not isinstance(item, dict):
            continue
        package = item.get('package') if isinstance(item.get('package'), dict) else {}
        value = _parts(
            f"{package.get('ecosystem')}:{package.get('name')}"
            if package.get('ecosystem') and package.get('name') else package.get('name'),
            item.get('vulnerable_version_range'),
        )
        if value:
            values.append(value)
    return values


def _source_fields(document, source_collection, details):
    source = document.get('source') if isinstance(document.get('source'), dict) else {}
    fields = {
        'title': _first({}, document, 'title') or _first(details, {}, 'title', 'advisory_title', 'vulName'),
        'overview': _first(details, document, 'intro', 'summary', 'description', 'vulDesc', 'productDesc'),
        'impacts': _all(details, document, 'impact', 'impacts', 'severity'),
        'affected': _all(
            details, document, 'systems_affected', 'affected_systems', 'affected',
            'affected_products', 'affectedSystem', 'affectedProduct', 'product_names',
        ),
        'recommendations': _all(
            details, document, 'solutions', 'solution', 'recommendation', 'recommendations',
            'patch', 'mitigation', 'remediation',
        ),
        'reference_values': _all(
            details, document, 'references', 'reference_links', 'referUrl', 'publication_url',
            'solution_links', 'more_information_links',
        ),
        'related_values': _all(details, document, 'related_links', 'related_link'),
        'show_impacts': True,
        'show_affected': True,
        'affected_table': None,
    }

    severity_sources = {
        'avd', 'cisco', 'cnnvd', 'cnvd', 'cve', 'github_advisory', 'hikvision',
        'huawei_sa', 'juniper', 'paloalto', 'qianxin', 'splunk',
    }
    if source_collection in severity_sources:
        fields['impacts'] = _all({}, document, 'severity') or fields['impacts']

    if source_collection == 'avd':
        fields['affected'] = _dict_lines(
            details.get('affected_software'),
            ('vendor', 'product', 'version', 'impact'),
        )
    elif source_collection == 'cisco':
        fields['overview'] = details.get('summary') or fields['overview']
        fields['affected'] = _values(details.get('product_names'))
        fields['reference_values'] = _values([
            details.get('publication_url'), details.get('cvrf_url'), details.get('csaf_url'),
        ])
    elif source_collection == 'cnvd':
        fields['title'] = _cnvd_title(document, details) or fields['title']
        fields['affected'] = _values(details.get('affected_products'))
        fields['reference_values'] = _values(_path(details, 'raw_fields', '参考链接'))
    elif source_collection == 'cnnvd':
        fields['overview'] = details.get('vulDesc') or details.get('productDesc') or fields['overview']
        severity = _severity_label(document.get('severity') or details.get('hazardLevel'))
        fields['impacts'] = [severity] if severity else []
        fields['affected'] = _values([
            details.get('affectedProduct'), details.get('affectedSystem'), details.get('affectedVendor'),
        ])
        fields['recommendations'] = _values(details.get('patch'))
        fields['reference_values'] = _values(details.get('referUrl'))
    elif source_collection == 'cve':
        fields['title'] = details.get('title') or fields['title']
        fields['overview'] = _first({}, {'values': _nested_values(details.get('descriptions'), 'value')}, 'values')
        fields['affected'] = _values(details.get('affected_products'))
        fields['reference_values'] = _nested_values(details.get('references'), 'url')
    elif source_collection == 'github_advisory':
        fields['overview'] = details.get('description') or details.get('summary') or fields['overview']
        fields['affected'] = _github_affected(details)
        fields['recommendations'] = _nested_values(details.get('vulnerabilities'), 'first_patched_version')
        fields['reference_values'] = _values(details.get('references'))
    elif source_collection == 'hkcert':
        fields['impacts'] = _values(details.get('impact'))
        fields['affected'] = _values(details.get('systems_affected'))
        fields['recommendations'] = _values(details.get('solutions'))
        fields['reference_values'] = _values(details.get('solution_links'))
        fields['related_values'] = _values(details.get('related_links'))
    elif source_collection == 'huawei_sa':
        fields['show_affected'] = False
        fields['affected'] = []
    elif source_collection in {'govcert', 'infosec'}:
        fields['overview'] = details.get('description') or details.get('summary') or fields['overview']
        fields['impacts'] = _values(details.get('impact'))
        fields['affected'] = _values(details.get('affected_systems'))
        fields['recommendations'] = _values(details.get('recommendation'))
        fields['reference_values'] = _values(details.get('more_information_links'))
    elif source_collection == 'juniper':
        fields['affected'] = []
        fields['affected_table'] = _raw_table(details)
    elif source_collection == 'paloalto':
        fields['affected'] = _values(details.get('products'))
        fields['recommendations'] = _values([details.get('solution'), details.get('workarounds')])
    elif source_collection == 'qianxin':
        fields['overview'] = (
            _path(details, 'description', 'security_advisory')
            or _path(details, 'description', 'vulnerability_information', 'summary')
            or fields['overview']
        )
        fields['affected'] = _qianxin_affected(details)
        fields['recommendations'] = _values(_path(details, 'description', 'recommendations'))
        fields['reference_values'] = _values([
            details.get('reference_links'), _path(details, 'description', 'references'),
        ])
    elif source_collection == 'hikvision':
        fields['reference_values'] = []
    elif source_collection == 'ransomwarelive':
        fields['overview'] = details.get('press') or document.get('title') or fields['overview']
        fields['show_impacts'] = False
        fields['show_affected'] = False
    elif source_collection == 'zeroday':
        fields['show_impacts'] = False
        fields['show_affected'] = False
        fields['impacts'] = []
        fields['affected'] = []

    detail_url = source.get('detail_url')
    if detail_url:
        fields['reference_values'] = [detail_url, *fields['reference_values']]
    source_url = source.get('url')
    if source_url:
        fields['related_values'] = [source_url, *fields['related_values']]
    return fields


def normalize_newsletter(document, source_collection):
    details = _details(document, source_collection)
    fields = _source_fields(document, source_collection, details)
    references = _links(fields['reference_values'])
    related_links = _links(fields['related_values'])
    related_links = [link for link in related_links if link not in references]
    cves = _all(
        details, document, 'cve', 'cve_code', 'cveCode', 'cve_id', 'cve_ids',
        'vulnerability_identifiers',
    )
    cves = [value for value in cves if 'CVE-' in value.upper()]
    template_key = template_key_for_source(source_collection)
    is_chinese = template_key in CHINESE_TEMPLATE_KEYS
    severity = fields['impacts']
    impacts = []
    show_impacts = False
    if template_key == 'hkcert':
        severity = _values(details.get('risk_level')) or _all({}, document, 'severity', 'status')
        impacts = fields['impacts']
        show_impacts = True
    result = {
        'template_key': template_key,
        'language': 'zh-Hans' if is_chinese else 'en',
        'labels': CHINESE_LABELS if is_chinese else ENGLISH_LABELS,
        'title': fields['title'] or 'Security Advisory',
        'overview': _safe_html(fields['overview'] or 'No overview was provided in the source record.'),
        'severity': severity,
        'impacts': impacts,
        'affected': fields['affected'],
        'recommendations': fields['recommendations'],
        'references': references,
        'related_links': related_links,
        'cves': cves,
        'table': None,
        'affected_table': fields['affected_table'],
        'show_severity': fields['show_impacts'],
        'show_impacts': show_impacts,
        'show_affected': fields['show_affected'],
    }
    if template_key == 'hkcert':
        result['table'] = _hkcert_table(details)
    return result


def render_newsletter(document, source_collection):
    newsletter = normalize_newsletter(document, source_collection)
    template = f"newsletter/generated_{newsletter['template_key']}.html"
    return render_template(template, newsletter=newsletter), newsletter


def _fingerprint(document):
    document = dict(document)
    document.pop('html_json', None)
    payload = json_util.dumps(document, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _record_id(source_collection, selection_id):
    value = f'{source_collection}\0{selection_id}'.encode('utf-8')
    return hashlib.sha256(value).hexdigest()


DEFAULT_FEED_LIMIT = 100


def filter_newsletter_feed(database, email, filters, limit=DEFAULT_FEED_LIMIT, offset=0):
    validated = validate_filters(database, filters)
    matches = query_profile_matches(database, {'filters': validated}, limit=None)
    record_ids = [_record_id(match['source_collection'], match['selection_id']) for match in matches]
    if not record_ids:
        return [], 0

    query = {'_id': {'$in': record_ids}, 'subscription_emails': email}
    collection = get_newsletter_collection()
    collection.update_many(
        query,
        {'$unset': {'html': '', 'html_updated_at': '', 'html_path': ''}},
    )
    total = collection.count_documents(query)
    cursor = collection.find(
        query,
        {'html': 0, 'subscription_emails': 0, 'source_fingerprint': 0},
    ).sort('generated_at', -1).skip(offset)
    if limit is not None:
        cursor = cursor.limit(limit)

    data = []
    for document in cursor:
        document['id'] = str(document.pop('_id'))
        data.append(document)
    return data, total


def sync_newsletters():
    local = get_web_database()
    atlas = get_vulnerabilities_database()
    tracked = {}
    errors = []
    for raw_subscription in local['subscriptions'].find({}):
        try:
            subscription = normalize_subscription(atlas, raw_subscription)
            profile = subscription['newsletter_profile']
            if not profile['enabled']:
                continue
            for match in query_profile_matches(atlas, profile, limit=None):
                key = (match['source_collection'], match['selection_id'])
                tracked.setdefault(key, set()).add(subscription['email'])
        except (ValueError, TypeError) as exc:
            errors.append({'email': raw_subscription.get('email'), 'error': str(exc)})

    active_ids = []
    now = datetime.now(timezone.utc)
    collection = get_newsletter_collection()
    for (source_collection, selection_id), emails in tracked.items():
        document = resolve_vulnerability_document(atlas, source_collection, selection_id)
        if document is None:
            continue
        record_id = _record_id(source_collection, selection_id)
        active_ids.append(record_id)
        fingerprint = _fingerprint(document)
        existing = collection.find_one({'_id': record_id}, {'source_fingerprint': 1})
        normalized = normalize_newsletter(document, source_collection)
        update = {
            'source_collection': source_collection,
            'selection_id': selection_id,
            'subscription_emails': sorted(emails),
            'source_fingerprint': fingerprint,
            'template_key': template_key_for_source(source_collection),
            'title': normalized['title'],
            'updated_at': now,
        }
        if not existing or existing.get('source_fingerprint') != fingerprint:
            update['generated_at'] = now
        collection.update_one(
            {'_id': record_id},
            {'$set': update, '$unset': {'html': '', 'html_updated_at': '', 'html_path': ''}},
            upsert=True,
        )
    collection.delete_many({'_id': {'$nin': active_ids}})
    return {'tracked': len(active_ids), 'errors': errors}

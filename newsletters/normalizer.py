import re
from urllib.parse import urlparse

import bleach
import markdown
from flask import render_template
from markupsafe import Markup

ALLOWED_TAGS = {
    'a', 'b', 'blockquote', 'br', 'code', 'div', 'em', 'h2', 'h3', 'li', 'ol',
    'p', 'pre', 'span', 'strong', 'table', 'tbody', 'td', 'th', 'thead', 'tr', 'ul',
}
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'rel', 'target'],
    'td': ['colspan', 'rowspan'],
    'th': ['colspan', 'rowspan'],
}
GITHUB_ADVISORY_IMAGE_ATTRIBUTES = {'src', 'alt', 'title', 'width', 'height'}
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
    'collection': 'Source collection:',
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
    'collection': '来源集合：',
    'not_specified': '未说明',
    'default_recommendation': '请参考供应商指南并应用可用修复。',
    'footer': '如有任何疑问，请联系安全运营中心。谢谢。',
}
CVE_PATTERN = re.compile(r'\b(?:CVE-)?(\d{4}-\d{4,})\b', re.IGNORECASE)
SCRIPT_OR_STYLE_PATTERN = re.compile(
    r'<(?:script|style)\b[^>]*>.*?</(?:script|style)\s*>', re.IGNORECASE | re.DOTALL,
)


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


def _nested_field_values(value, fields):
    values = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in fields:
                values.extend(_values(item))
            values.extend(_nested_field_values(item, fields))
    elif isinstance(value, list):
        for item in value:
            values.extend(_nested_field_values(item, fields))
    return list(dict.fromkeys(values))


def _with_nested_fallback(values, details, document, fields):
    return values or _nested_field_values(details, fields) or _nested_field_values(document, fields)


def _is_https_url(value):
    parsed = urlparse(str(value or ''))
    return parsed.scheme == 'https' and bool(parsed.netloc)


def _github_advisory_attributes(tag, name, value):
    if tag == 'img':
        if name == 'src':
            return _is_https_url(value)
        if name in {'width', 'height'}:
            return str(value).isdigit()
        return name in GITHUB_ADVISORY_IMAGE_ATTRIBUTES
    return name in ALLOWED_ATTRIBUTES.get(tag, [])


def _safe_html(value, *, allow_images=False):
    tags = ALLOWED_TAGS | ({'img'} if allow_images else set())
    attributes = _github_advisory_attributes if allow_images else ALLOWED_ATTRIBUTES
    return Markup(bleach.clean(
        str(value or ''),
        tags=tags,
        attributes=attributes,
        protocols={'http', 'https', 'mailto'},
        strip=True,
    ))


def _github_advisory_overview(value):
    source = SCRIPT_OR_STYLE_PATTERN.sub('', str(value or ''))
    rendered = markdown.markdown(source, extensions=['extra', 'sane_lists'])
    return _safe_html(rendered, allow_images=True)


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


def _cve_values(values):
    cves = []
    seen = set()
    for value in _values(values):
        for match in CVE_PATTERN.findall(str(value)):
            cve = f'CVE-{match.upper()}'
            if cve not in seen:
                seen.add(cve)
                cves.append(cve)
    return cves


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


def _cve_affected(values):
    result = []
    for item in values or []:
        if not isinstance(item, dict):
            continue
        versions = item.get('versions') or [{}]
        for version in versions:
            if not isinstance(version, dict):
                continue
            version_text = (
                f"<= {version['lessThanOrEqual']}" if version.get('lessThanOrEqual')
                else f"< {version['lessThan']}" if version.get('lessThan')
                else version.get('version') if version.get('version') not in {'', '0'} else ''
            )
            value = _parts(item.get('vendor'), item.get('product'), version_text)
            if value and value not in result:
                result.append(value)
    return result


def _path(value, *fields):
    for field in fields:
        if not isinstance(value, dict):
            return None
        value = value.get(field)
    return value


def _cnvd_title(document, details):
    raw_title = _path(details, 'raw_fields', '厂商补丁')
    if str(raw_title or '').strip() in {'(无补丁信息)', '（无补丁信息）'}:
        raw_title = ''
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


def _avd_source_fields(fields, document, details):
    fields['affected'] = _dict_lines(
        details.get('affected_software'),
        ('vendor', 'product', 'version', 'impact'),
    )


def _cisco_source_fields(fields, document, details):
    fields['overview'] = details.get('summary') or fields['overview']
    fields['affected'] = _values(details.get('product_names'))
    fields['reference_values'] = _values([
        details.get('publication_url'), details.get('cvrf_url'), details.get('csaf_url'),
    ])


def _cnvd_source_fields(fields, document, details):
    fields['title'] = _cnvd_title(document, details) or fields['title']
    fields['affected'] = _values(details.get('affected_products'))
    fields['reference_values'] = _values(_path(details, 'raw_fields', '参考链接'))


def _cnnvd_source_fields(fields, document, details):
    fields['overview'] = details.get('vulDesc') or details.get('productDesc') or fields['overview']
    severity = _severity_label(document.get('severity') or details.get('hazardLevel'))
    fields['impacts'] = [severity] if severity else []
    fields['affected'] = _values([
        details.get('affectedProduct'), details.get('affectedSystem'), details.get('affectedVendor'),
    ])
    fields['recommendations'] = _values(details.get('patch'))
    fields['reference_values'] = _values(details.get('referUrl'))


def _cve_source_fields(fields, document, details):
    fields['overview'] = _first(
        {}, {'values': _nested_values(details.get('descriptions'), 'value')}, 'values',
    )
    fields['affected'] = _cve_affected(details.get('affected'))
    fields['reference_values'] = _nested_values(details.get('references'), 'url')


def _github_advisory_source_fields(fields, document, details):
    fields['overview'] = details.get('description') or details.get('summary') or fields['overview']
    fields['affected'] = _github_affected(details)
    fields['recommendations'] = _nested_values(details.get('vulnerabilities'), 'first_patched_version')
    fields['reference_values'] = _values(details.get('references'))


def _hkcert_source_fields(fields, document, details):
    fields['impacts'] = _values(details.get('impact'))
    fields['affected'] = _values(details.get('systems_affected'))
    fields['recommendations'] = _values(details.get('solutions'))
    fields['reference_values'] = _values(details.get('solution_links'))
    fields['related_values'] = _values(details.get('related_links'))


def _huawei_sa_source_fields(fields, document, details):
    fields['show_affected'] = False
    fields['affected'] = []


def _govcert_infosec_source_fields(fields, document, details):
    fields['overview'] = details.get('description') or details.get('summary') or fields['overview']
    fields['impacts'] = _values(details.get('impact'))
    fields['affected'] = _values(details.get('affected_systems'))
    fields['recommendations'] = _values(details.get('recommendation'))
    fields['reference_values'] = _values(details.get('more_information_links'))


def _juniper_source_fields(fields, document, details):
    fields['affected'] = []
    fields['affected_table'] = _raw_table(details)


def _paloalto_source_fields(fields, document, details):
    fields['affected'] = _values(details.get('products'))
    fields['recommendations'] = _values([details.get('solution'), details.get('workarounds')])


def _qianxin_source_fields(fields, document, details):
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


def _hikvision_source_fields(fields, document, details):
    fields['reference_values'] = []


def _ransomwarelive_source_fields(fields, document, details):
    fields['overview'] = details.get('press') or document.get('title') or fields['overview']
    fields['show_impacts'] = False
    fields['show_affected'] = False


def _zeroday_source_fields(fields, document, details):
    fields['show_impacts'] = False
    fields['show_affected'] = False
    fields['impacts'] = []
    fields['affected'] = []


SOURCE_FIELD_OVERRIDES = {
    'avd': _avd_source_fields,
    'cisco': _cisco_source_fields,
    'cnvd': _cnvd_source_fields,
    'cnnvd': _cnnvd_source_fields,
    'cve': _cve_source_fields,
    'github_advisory': _github_advisory_source_fields,
    'hkcert': _hkcert_source_fields,
    'huawei_sa': _huawei_sa_source_fields,
    'govcert': _govcert_infosec_source_fields,
    'infosec': _govcert_infosec_source_fields,
    'juniper': _juniper_source_fields,
    'paloalto': _paloalto_source_fields,
    'qianxin': _qianxin_source_fields,
    'hikvision': _hikvision_source_fields,
    'ransomwarelive': _ransomwarelive_source_fields,
    'zeroday': _zeroday_source_fields,
}
SEVERITY_DOCUMENT_SOURCES = {
    'avd', 'cisco', 'cnnvd', 'cnvd', 'cve', 'github_advisory', 'hikvision',
    'huawei_sa', 'juniper', 'paloalto', 'qianxin', 'splunk',
}


def _default_source_fields(document, details):
    overview = _first(details, document, 'intro', 'summary', 'description', 'vulDesc', 'productDesc')
    return {
        'title': _first({}, document, 'title') or _first(details, {}, 'title', 'advisory_title', 'vulName'),
        'overview': overview or (_nested_field_values(
            details, ('intro', 'summary', 'description', 'overview', 'vulDesc', 'productDesc')
        ) or [''])[0],
        'impacts': _with_nested_fallback(
            _all(details, document, 'impact', 'impacts', 'severity'), details, document,
            ('impact', 'impacts', 'severity'),
        ),
        'affected': _with_nested_fallback(_all(
            details, document, 'systems_affected', 'affected_systems', 'affected',
            'affected_products', 'affectedSystem', 'affectedProduct', 'product_names',
        ), details, document, (
            'systems_affected', 'affected_systems', 'affected', 'affected_products',
            'affectedSystem', 'affectedProduct', 'product_names',
        )),
        'recommendations': _with_nested_fallback(_all(
            details, document, 'solutions', 'solution', 'recommendation', 'recommendations',
            'patch', 'mitigation', 'remediation',
        ), details, document, (
            'solutions', 'solution', 'recommendation', 'recommendations', 'patch',
            'mitigation', 'remediation',
        )),
        'reference_values': _with_nested_fallback(_all(
            details, document, 'references', 'reference_links', 'referUrl', 'publication_url',
            'solution_links', 'more_information_links',
        ), details, document, (
            'references', 'reference_links', 'referUrl', 'publication_url', 'solution_links',
            'more_information_links',
        )),
        'related_values': _with_nested_fallback(
            _all(details, document, 'related_links', 'related_link'), details, document,
            ('related_links', 'related_link'),
        ),
        'show_impacts': True,
        'show_affected': True,
        'affected_table': None,
    }


def _source_fields(document, source_collection, details):
    source = document.get('source') if isinstance(document.get('source'), dict) else {}
    fields = _default_source_fields(document, details)

    if source_collection in SEVERITY_DOCUMENT_SOURCES:
        fields['impacts'] = _all({}, document, 'severity') or fields['impacts']

    override = SOURCE_FIELD_OVERRIDES.get(source_collection)
    if override is not None:
        override(fields, document, details)

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
    cves = _cve_values(_all(
        details, document, 'cve', 'cve_code', 'cve_codes', 'cveCode', 'cve_id', 'cve_ids',
        'vulnerability_identifiers',
    ))
    template_key = template_key_for_source(source_collection)
    is_chinese = template_key in CHINESE_TEMPLATE_KEYS
    severity = fields['impacts']
    impacts = []
    show_impacts = False
    if template_key == 'hkcert':
        severity = _values(details.get('risk_level')) or _all({}, document, 'severity', 'status')
        impacts = fields['impacts']
        show_impacts = True
    overview = fields['overview'] or 'No overview was provided in the source record.'
    if source_collection == 'github_advisory':
        overview = _github_advisory_overview(overview)
    else:
        overview = _safe_html(overview)
    result = {
        'template_key': template_key,
        'language': 'zh-Hans' if is_chinese else 'en',
        'labels': CHINESE_LABELS if is_chinese else ENGLISH_LABELS,
        'title': fields['title'] or 'Security Advisory',
        'collection': source_collection,
        'overview': overview,
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
    return render_template('newsletters/generated.html', newsletter=newsletter), newsletter

import html
import json
import re
from string import Template

from jsonschema import validate

from core.prompts import DEFAULT_PROMPTS
from newsletters.normalizer import normalize_newsletter
from core.database import get_vulnerabilities_database
from reviews.repository import resolve_vulnerability_document



DEFAULT_JSON_ERROR_MESSAGE = DEFAULT_PROMPTS['json_error_message']
REPORT_TEMPLATE = 'reports/generated.html'
ENRICHED_REPORT_TEMPLATE = 'reports/enriched.html'
GENERATION_MODES = {'template', 'enriched_weekly'}
LEGACY_GENERATION_MODES = {'ai': 'enriched_weekly', 'company_ai': 'enriched_weekly'}
REPORT_LANGUAGES = {
    'en': 'English',
    'zh': 'Traditional Chinese',
    'ch': 'Simplified Chinese',
}
TRANSLATION_LANGUAGES = {'zh', 'ch'}
HTML_LANGUAGE_CODES = {'en': 'en', 'zh': 'zh-Hant', 'ch': 'zh-Hans'}
REPORT_LABELS = {
    'en': {
        'report_title': 'Cybersecurity Report',
        'generated': 'Generated {date} from {count} source records.',
        'executive_summary': 'Executive Summary',
        'important_vulnerabilities': 'Important Vulnerabilities',
        'trends': 'Trends',
        'high_priority_vulnerabilities': 'High-Priority Vulnerabilities',
        'affected': 'Affected',
        'references': 'References',
        'recommended_actions': 'Recommended Actions',
        'strategic_recommendations': 'Strategic Recommendations',
    },
    'zh': {
        'report_title': '網絡安全報告',
        'generated': '於 {date} 根據 {count} 筆來源記錄產生。',
        'executive_summary': '執行摘要',
        'important_vulnerabilities': '重要漏洞',
        'trends': '趨勢',
        'high_priority_vulnerabilities': '高優先級漏洞',
        'affected': '受影響項目',
        'references': '參考資料',
        'recommended_actions': '建議措施',
        'strategic_recommendations': '策略建議',
    },
    'ch': {
        'report_title': '网络安全报告',
        'generated': '于 {date} 根据 {count} 条来源记录生成。',
        'executive_summary': '执行摘要',
        'important_vulnerabilities': '重要漏洞',
        'trends': '趋势',
        'high_priority_vulnerabilities': '高优先级漏洞',
        'affected': '受影响项目',
        'references': '参考资料',
        'recommended_actions': '建议措施',
        'strategic_recommendations': '战略建议',
    },
}
ENRICHED_REPORT_LABELS = {
    'en': {
        'generated': 'Generated {date} from {count} CVE candidate(s).',
        'executive_summary': 'Executive Summary',
        'vulnerability_cards': 'Vulnerability Cards',
        'cve': 'CVE',
        'vendor': 'Vendor',
        'product': 'Product',
        'severity': 'Severity',
        'vulnerability_overview': 'Vulnerability Overview',
        'risk_and_impact': 'Risk and Impact',
        'remediation_guidance': 'Remediation Guidance',
        'source_references': 'Source References',
    },
    'zh': {
        'generated': '於 {date} 根據 {count} 個 CVE 候選項目產生。',
        'executive_summary': '執行摘要',
        'vulnerability_cards': '漏洞卡片',
        'cve': 'CVE',
        'vendor': '供應商',
        'product': '產品',
        'severity': '嚴重程度',
        'vulnerability_overview': '漏洞概述',
        'risk_and_impact': '風險與影響',
        'remediation_guidance': '修復指引',
        'source_references': '來源參考',
    },
    'ch': {
        'generated': '于 {date} 根据 {count} 个 CVE 候选项生成。',
        'executive_summary': '执行摘要',
        'vulnerability_cards': '漏洞卡片',
        'cve': 'CVE',
        'vendor': '供应商',
        'product': '产品',
        'severity': '严重程度',
        'vulnerability_overview': '漏洞概述',
        'risk_and_impact': '风险与影响',
        'remediation_guidance': '修复指引',
        'source_references': '来源参考',
    },
}
HIGHLIGHT_TABLE_SCHEMA = {
    'type': 'object',
    'required': ['headers', 'rows'],
    'properties': {
        'caption': {'type': 'string'},
        'headers': {
            'type': 'array',
            'items': {'type': 'string'},
            'minItems': 1,
            'maxItems': 12,
        },
        'rows': {
            'type': 'array',
            'maxItems': 50,
            'items': {
                'type': 'array',
                'items': {'type': 'string'},
            },
        },
    },
}
HIGHLIGHT_PROPERTIES = {
    'title': {'type': 'string'},
    'code': {'type': 'string'},
    'severity': {'type': 'string'},
    'summary': {'type': 'string'},
    'affected': {'type': 'array', 'items': {'type': 'string'}},
    'references': {'type': 'array', 'items': {'type': 'string'}},
    'table': HIGHLIGHT_TABLE_SCHEMA,
    'source_link': {'type': 'string'},
    'newsletter': {'type': 'object'},
}
REPORT_HIGHLIGHT_SCHEMA = {
    'type': 'object',
    'required': ['title', 'summary'],
    'properties': HIGHLIGHT_PROPERTIES,
}
REPORT_SCHEMA = {
    'type': 'object',
    'required': ['title', 'executive_summary', 'highlights', 'trends', 'recommendations'],
    'properties': {
        'title': {'type': 'string'},
        'executive_summary': {'type': 'string'},
        'highlights': {
            'type': 'array',
            'items': REPORT_HIGHLIGHT_SCHEMA,
        },
        'trends': {'type': 'array', 'items': {'type': 'string'}},
        'recommendations': {'type': 'array', 'items': {'type': 'string'}},
    },
}
def _fixed_report_title(report_language):
    labels = REPORT_LABELS.get(report_language, REPORT_LABELS['en'])
    return labels['report_title']


def _clean(value, depth=0):
    if depth > 5:
        return None
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if key == 'raw':
                continue
            result = _clean(item, depth + 1)
            if result not in (None, '', [], {}):
                cleaned[key] = result
        return cleaned
    if isinstance(value, list):
        cleaned = [_clean(item, depth + 1) for item in value[:100]]
        return [item for item in cleaned if item not in (None, '', [], {})]
    if isinstance(value, str):
        return value[:12000]
    if value is None:
        return None
    return value


def compact_document(document):
    details = document.get('details') or {}
    detail_fields = {
        'description', 'summary', 'impacts', 'impact', 'severity', 'status',
        'affected', 'affected_products', 'systems_affected', 'recommendation',
        'recommendations', 'solution', 'solutions', 'remediation', 'mitigation',
        'mitigations', 'references', 'reference_links', 'related_links',
    }
    if isinstance(details, dict) and detail_fields.intersection(details):
        normalized = details
    elif isinstance(details, dict):
        normalized = next(
            (value for value in details.values() if isinstance(value, dict)),
            {},
        )
    else:
        normalized = {}
    compacted = _clean({
        'id': str(document.get('_id', '')),
        'type': document.get('type'),
        'code': document.get('cve_code') or document.get('cve') or document.get('code'),
        'cve_codes': document.get('cve_codes'),
        'title': document.get('title'),
        'vulnerability_type': document.get('vuln_type'),
        'disclosure_date': document.get('disclosure_date'),
        'scraped_at': document.get('scraped_at'),
        'status': document.get('status'),
        'severity': document.get('severity'),
        'summary': document.get('summary') or document.get('description') or document.get('impacts'),
        'affected': document.get('affected') or document.get('affected_products'),
        'recommendations': (
            document.get('recommendations')
            or document.get('recommendation')
            or document.get('solutions')
            or document.get('solution')
        ),
        'references': document.get('references') or document.get('reference_links'),
        'source': document.get('source'),
        'details': normalized,
    })
    if estimate_tokens(compacted) > 12000:
        compacted['details'] = {
            'description': str(normalized.get('description') or normalized.get('summary') or '')[:12000],
            'affected': _clean(
                normalized.get('affected')
                or normalized.get('affected_products')
                or normalized.get('systems_affected')
                or [],
            ),
            'recommendation': str(
                normalized.get('recommendation')
                or normalized.get('solution')
                or normalized.get('solutions')
                or '',
            )[:8000],
            'references': _clean(
                normalized.get('references')
                or normalized.get('reference_links')
                or normalized.get('related_links')
                or [],
            ),
        }
        compacted = _clean(compacted)
    return compacted


def compact_details(details, config):
    deny_keys = {str(key).casefold() for key in config['REPORT_DENY_KEYS']}
    deny_prefixes = tuple(str(prefix).casefold() for prefix in config['REPORT_DENY_PREFIXES'])
    max_depth = config['REPORT_MAX_DEPTH']
    max_list = config['REPORT_MAX_LIST_ITEMS']
    max_string = config['REPORT_MAX_STRING_CHARS']

    def clean(value, depth=0):
        if depth > max_depth:
            return None
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                normalized = str(key).casefold()
                if normalized in deny_keys or normalized.startswith(deny_prefixes):
                    continue
                cleaned = clean(item, depth + 1)
                if cleaned not in (None, '', [], {}):
                    result[str(key)] = cleaned
            return result
        if isinstance(value, (list, tuple, set)):
            result = []
            seen = set()
            for item in list(value)[:max_list]:
                cleaned = clean(item, depth + 1)
                if cleaned in (None, '', [], {}):
                    continue
                marker = json.dumps(cleaned, ensure_ascii=False, sort_keys=True, default=str)
                if marker not in seen:
                    seen.add(marker)
                    result.append(cleaned)
            return result
        if isinstance(value, str):
            return ' '.join(html.unescape(value).split())[:max_string]
        if value is None:
            return None
        return value

    if not isinstance(details, dict):
        raise ValueError('Each report input must contain a details object.')
    return clean(details)


def compact_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), default=str)


def estimate_tokens(value):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return max(1, (len(text) + 3) // 4)


def json_error_prompt(provider, error):
    template = getattr(provider, 'json_error_message', DEFAULT_JSON_ERROR_MESSAGE)
    return Template(template).safe_substitute(error=str(error))


def _strip_html(value):
    if value in (None, ''):
        return ''
    text = html.unescape(str(value))
    text = re.sub(r'<br\s*/?>', ' ', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    return ' '.join(html.unescape(text).split())


def _string_values(value):
    if value in (None, ''):
        return []
    if isinstance(value, dict):
        values = []
        for item in value.values():
            values.extend(_string_values(item))
        return values
    if isinstance(value, (list, tuple, set)):
        values = []
        for item in value:
            values.extend(_string_values(item))
        return values
    return [str(value).strip()]


def _unique_strings(*values):
    unique = []
    seen = set()
    for value in values:
        for item in _string_values(value):
            key = item.casefold()
            if item and key not in seen:
                seen.add(key)
                unique.append(item)
    return unique


def _first_value(record, details, *fields):
    for source in (record, details):
        for field in fields:
            values = _unique_strings(source.get(field))
            if values:
                return values[0]
    return ''


def _all_values(record, details, *fields):
    return _unique_strings(*[
        source.get(field)
        for source in (record, details)
        for field in fields
    ])


def _template_first_value(record, details, *fields):
    return _strip_html(_first_value(record, details, *fields))


def _template_all_values(record, details, *fields):
    return [_strip_html(value) for value in _all_values(record, details, *fields)]


def _normalized_details_root(details):
    if not isinstance(details, dict):
        return {}
    if len(details) == 1:
        inner = next(iter(details.values()))
        return inner if isinstance(inner, dict) else details
    return details


def _item_title_from_details(details, identifier, position, record=None):
    record = record if isinstance(record, dict) else {}
    normalized = _normalized_details_root(details)
    title = _template_first_value(record, normalized, 'title', 'vulName', 'advisory_title')
    code = _template_first_value(record, normalized, 'code', 'cve', 'cve_code', 'cveCode', 'cnnvdCode')
    return title or code or identifier or f'Vulnerability record {position}'


def _finalize_item_result(result, details, identifier, position, record=None):
    finalized = dict(result)
    highlight = dict(finalized.get('highlight') or {})
    highlight['title'] = _item_title_from_details(details, identifier, position, record)
    finalized['highlight'] = highlight
    return finalized


def _source_record_for_item(item):
    record = {}
    if isinstance(item.get('source_record'), dict):
        record.update(item['source_record'])
    if item.get('source_collection') and item.get('selection_id'):
        document = resolve_vulnerability_document(
            get_vulnerabilities_database(),
            item['source_collection'],
            item['selection_id'],
            {
                'title': 1, 'code': 1, 'cve': 1, 'cve_code': 1, 'severity': 1,
                'status': 1, 'source': 1, 'type': 1,
            },
        )
        if document:
            for field in ('title', 'code', 'cve', 'cve_code', 'severity', 'status', 'source', 'type'):
                if document.get(field):
                    record.setdefault(field, document[field])
        record['source_collection'] = item['source_collection']
    return record


def _source_link_from_record(record, newsletter):
    source = record.get('source') if isinstance(record.get('source'), dict) else {}
    for value in (
        source.get('detail_url'),
        source.get('url'),
        *(newsletter.get('references') or []),
        *(newsletter.get('related_links') or []),
    ):
        if value:
            return str(value)
    return ''


def _newsletter_payload(newsletter):
    payload = {
        'overview': str(newsletter.get('overview') or ''),
        'severity': newsletter.get('severity') or [],
        'impacts': newsletter.get('impacts') or [],
        'affected': newsletter.get('affected') or [],
        'cves': newsletter.get('cves') or [],
        'recommendations': newsletter.get('recommendations') or [],
        'references': newsletter.get('references') or [],
        'related_links': newsletter.get('related_links') or [],
        'table': newsletter.get('table'),
        'affected_table': newsletter.get('affected_table'),
        'show_severity': bool(newsletter.get('show_severity')),
        'show_impacts': bool(newsletter.get('show_impacts')),
        'show_affected': bool(newsletter.get('show_affected')),
        'labels': newsletter.get('labels') or {},
    }
    return _clean(payload) or {}


def _template_highlights(records):
    highlights = []
    for position, record in enumerate(records, start=1):
        details = record.get('details') if isinstance(record.get('details'), dict) else {}
        source_collection = (
            record.get('source_collection')
            or record.get('type')
            or record.get('collection')
            or 'generic'
        )
        document = {**record, 'details': details}
        newsletter = normalize_newsletter(document, source_collection)
        newsletter_title = newsletter.get('title')
        if newsletter_title == 'Security Advisory':
            newsletter_title = ''
        title = (
            _template_first_value(record, details, 'title', 'vulName', 'advisory_title')
            or _template_first_value(record, details, 'code', 'cve', 'cve_code', 'cveCode', 'cnnvdCode')
            or newsletter_title
            or f'Vulnerability record {position}'
        )
        severity = (
            _template_first_value(record, details, 'severity', 'status', 'risk', 'priority', 'hazardLevel')
            or next(iter(newsletter.get('severity') or []), '')
        )
        highlights.append({
            'title': title,
            'code': _template_first_value(
                record, details, 'code', 'cve', 'cve_code', 'cveCode', 'cnnvdCode',
            ),
            'severity': severity,
            'summary': _strip_html(str(newsletter.get('overview') or '')),
            'affected': newsletter.get('affected') or [],
            'references': newsletter.get('references') or [],
            'source_link': _source_link_from_record(record, newsletter),
            'newsletter': _newsletter_payload(newsletter),
        })
    return highlights


def _deterministic_report_sections(records):
    recommendations = []
    severities = {}
    affected_counts = {}
    affected_record_count = 0
    recommendation_record_count = 0
    reference_record_count = 0
    for record in records:
        details = record.get('details') if isinstance(record.get('details'), dict) else {}
        severity = _template_first_value(
            record, details, 'severity', 'status', 'risk', 'priority', 'hazardLevel',
        )
        affected = _template_all_values(
            record, details,
            'affected', 'affected_products', 'systems_affected', 'products',
            'affectedProduct', 'affectedSystem', 'affectedVendor',
        )
        references = _template_all_values(
            record, details,
            'references', 'reference_links', 'related_links', 'urls', 'referUrl',
        )
        record_recommendations = _template_all_values(
            record, details,
            'recommendation', 'recommendations', 'solution', 'solutions',
            'remediation', 'mitigation', 'mitigations', 'patch',
        )
        recommendations.extend(record_recommendations)
        if severity:
            severity_key = severity.casefold()
            if severity_key not in severities:
                severities[severity_key] = {'label': severity, 'count': 0}
            severities[severity_key]['count'] += 1
        if affected:
            affected_record_count += 1
            for value in affected:
                affected_key = value.casefold()
                if affected_key not in affected_counts:
                    affected_counts[affected_key] = {'label': value, 'count': 0}
                affected_counts[affected_key]['count'] += 1
        recommendation_record_count += int(bool(record_recommendations))
        reference_record_count += int(bool(references))

    severity_summary = ', '.join(
        f"{item['label']}: {item['count']}"
        for item in sorted(severities.values(), key=lambda item: item['label'].casefold())
    )
    affected_summary = ', '.join(
        f"{item['label']}: {item['count']}"
        for item in sorted(
            affected_counts.values(),
            key=lambda item: (-item['count'], item['label'].casefold()),
        )[:5]
    )
    total = len(records)
    severity_record_count = sum(item['count'] for item in severities.values())
    executive_summary = (
        f'This report contains {total} vulnerability '
        f'{"record" if total == 1 else "records"}. '
        f'Severity or status data is available for {severity_record_count} of {total} records. '
        f'Affected product or system data is available for {affected_record_count} of {total} '
        f'records. Remediation guidance is available for {recommendation_record_count} of '
        f'{total} records.'
    )

    trends = [
        f'Severity or status coverage: {severity_record_count} of {total} records.',
        f'Affected product or system coverage: {affected_record_count} of {total} records.',
        f'Remediation guidance coverage: {recommendation_record_count} of {total} records.',
        f'Reference coverage: {reference_record_count} of {total} records.',
    ]
    if severity_summary:
        trends[0] += f' Distribution: {severity_summary}.'
    if affected_summary:
        trends[1] += f' Most frequently affected: {affected_summary}.'

    return executive_summary, trends, _unique_strings(recommendations) or [
        'No recommendations were provided in the source records.',
    ]


def generate_template_report_data(records):
    if not records:
        raise ValueError('At least one vulnerability record is required.')

    report = {
        'title': _fixed_report_title('en'),
        'executive_summary': '',
        'highlights': _template_highlights(records),
        'trends': [],
        'recommendations': [],
        'template_mode': True,
    }
    validate(instance=report, schema=REPORT_SCHEMA)
    return report

import html
import json
import os
import re
import threading
from datetime import datetime, timezone
from string import Template

from bson import ObjectId, json_util
from flask import current_app, render_template
from jsonschema import validate
from pymongo import ReturnDocument

from newsletter_store import normalize_newsletter
from mongo import get_vulnerabilities_database, get_web_database
from report_job_progress import (
    append_job_log,
    init_job_progress,
    mark_job_started,
    update_job_progress,
)
from review_data import (
    MAX_EXPORT_SELECTIONS,
    canonical_selection_id,
    resolve_vulnerability_document,
    review_views,
)



DEFAULT_JSON_ERROR_MESSAGE = (
    'The JSON above is invalid.\n\nError:\n${error}\n\n'
    'Fix it and return only valid JSON. No Markdown, no explanation, no extra text. '
    'Keep the original fields and meaning. Make only the minimum changes needed so it can parse '
    'with `json.loads()`.'
)
REPORT_TEMPLATE = 'generated_report.html'
ENRICHED_REPORT_TEMPLATE = 'enriched_report.html'
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
        'research_scope': 'Research Scope',
        'weekly_risk_trend': 'Weekly Risk Trend',
        'vulnerability_detail_table': 'Vulnerability Detail Table',
        'cve': 'CVE',
        'vendor': 'Vendor',
        'product': 'Product',
        'severity': 'Severity',
        'priority': 'Priority',
        'vulnerability_overview': 'Vulnerability Overview',
        'risk_and_impact': 'Risk and Impact',
        'remediation_guidance': 'Remediation Guidance',
        'remediation_playbook': 'Remediation Playbook',
        'management_brief': 'Management Brief',
        'business_impact': 'Business impact',
        'appendix': 'Appendix',
        'source_references': 'Source References',
    },
    'zh': {
        'generated': '於 {date} 根據 {count} 個 CVE 候選項目產生。',
        'executive_summary': '執行摘要',
        'research_scope': '研究範圍',
        'weekly_risk_trend': '每週風險趨勢',
        'vulnerability_detail_table': '漏洞詳情表',
        'cve': 'CVE',
        'vendor': '供應商',
        'product': '產品',
        'severity': '嚴重程度',
        'priority': '優先級',
        'vulnerability_overview': '漏洞概述',
        'risk_and_impact': '風險與影響',
        'remediation_guidance': '修復指引',
        'remediation_playbook': '修復行動方案',
        'management_brief': '管理層簡報',
        'business_impact': '業務影響',
        'appendix': '附錄',
        'source_references': '來源參考',
    },
    'ch': {
        'generated': '于 {date} 根据 {count} 个 CVE 候选项生成。',
        'executive_summary': '执行摘要',
        'research_scope': '研究范围',
        'weekly_risk_trend': '每周风险趋势',
        'vulnerability_detail_table': '漏洞详情表',
        'cve': 'CVE',
        'vendor': '供应商',
        'product': '产品',
        'severity': '严重程度',
        'priority': '优先级',
        'vulnerability_overview': '漏洞概述',
        'risk_and_impact': '风险与影响',
        'remediation_guidance': '修复指引',
        'remediation_playbook': '修复行动方案',
        'management_brief': '管理层简报',
        'business_impact': '业务影响',
        'appendix': '附录',
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


def resolve_review_selections(selections):
    if not isinstance(selections, list) or not selections or len(selections) > MAX_EXPORT_SELECTIONS:
        raise ValueError('Select between 1 and 500 vulnerability records.')
    database = get_vulnerabilities_database()
    views = review_views(database)
    inputs = []
    for selection in selections:
        view = views.get(selection.get('collection')) if isinstance(selection, dict) else None
        selection_id = selection.get('selection_id') if isinstance(selection, dict) else None
        if view is None or not isinstance(selection_id, str):
            raise ValueError('Invalid Vulnerability Reviews selection.')
        source_collection = view['options']['viewOn']
        document = resolve_vulnerability_document(
            database,
            source_collection,
            selection_id,
            {'_id': 1},
        )
        if document is None:
            raise ValueError(f'Selected vulnerability not found: {selection_id}')
        resolved_id = canonical_selection_id(document)
        inputs.append({
            'collection': selection['collection'],
            'source_collection': source_collection,
            'selection_id': resolved_id,
        })
    return inputs


def _job_collection():
    return get_web_database()['report_jobs']


def _input_collection():
    return get_web_database()['report_job_inputs']


def _result_collection():
    return get_web_database()['report_job_results']


def create_job(inputs, input_source, generation_mode='enriched_weekly', report_language='en'):
    if not inputs:
        raise ValueError('At least one vulnerability record is required.')
    generation_mode = LEGACY_GENERATION_MODES.get(generation_mode, generation_mode)
    if generation_mode not in GENERATION_MODES:
        raise ValueError('Generation mode must be "template" or "enriched_weekly".')
    if report_language not in REPORT_LANGUAGES:
        raise ValueError('Report language must be "en", "zh", or "ch".')
    report_language = 'en'
    if len(inputs) > MAX_EXPORT_SELECTIONS:
        raise ValueError(f'Reports are limited to {MAX_EXPORT_SELECTIONS} vulnerability records.')
    queued_inputs = []
    for position, item in enumerate(inputs):
        if input_source == 'review_selections':
            if generation_mode == 'enriched_weekly' and (
                item.get('collection') != 'cve_review' or item.get('source_collection') != 'cve'
            ):
                raise ValueError('enriched_weekly reports only support cve_review selections.')
            queued = {
                'source_collection': item['source_collection'],
                'selection_id': item['selection_id'],
                'identifier': item['selection_id'],
            }
        else:
            if generation_mode == 'enriched_weekly':
                raise ValueError('enriched_weekly reports require cve_review selections, not uploaded JSON.')
            if not isinstance(item.get('details'), dict):
                raise ValueError('Each uploaded document must contain a details object.')
            source_record = {
                key: item[key]
                for key in ('title', 'code', 'cve', 'cve_code')
                if item.get(key)
            }
            queued = {
                'details': item['details'],
                'identifier': str(item.get('_id') or item.get('code') or item.get('title') or position + 1),
            }
            if source_record:
                queued['source_record'] = source_record
        queued_inputs.append({'position': position, **queued})
    now = datetime.now(timezone.utc)
    if generation_mode == 'enriched_weekly':
        provider = 'Tavily + llama-server'
        model = 'Enriched Weekly'
    else:
        provider = None
        model = 'Fixed Template'
    job = {
        'generation_mode': generation_mode,
        'effective_generation_mode': generation_mode,
        'report_language': report_language,
        'effective_report_language': report_language,
        'input_source': input_source,
        'source_count': len(inputs),
        'processed_count': 0,
        'current_position': 0,
        'item_fallback_count': 0,
        'status': 'queued' if generation_mode == 'enriched_weekly' else 'running',
        'created_at': now,
        'updated_at': now,
        'provider': provider,
        'model': model,
        'progress_percent': 0,
        'progress_current': 0,
        'progress_total': max(len(inputs), 1),
        'progress_label': None,
        'status_message': None,
        'estimated_seconds_remaining': None,
        'started_at': now if generation_mode == 'template' else None,
        'pipeline_logs': [],
    }
    job_id = _job_collection().insert_one(job).inserted_id
    _input_collection().insert_many([
        {'job_id': job_id, **item}
        for item in queued_inputs
    ])
    return str(job_id)


def _load_input_details(item):
    if 'details' in item:
        return item['details']
    document = resolve_vulnerability_document(
        get_vulnerabilities_database(),
        item['source_collection'],
        item['selection_id'],
        {'details': 1, '_id': 1},
    )
    if document is None:
        raise ValueError(f"Selected vulnerability not found: {item['selection_id']}")
    details = document.get('details')
    if not isinstance(details, dict):
        raise ValueError(f"Selected vulnerability has no details object: {item['selection_id']}")
    return details


def _local_item(details):
    normalized = next(iter(details.values()), details) if len(details) == 1 else details
    report = generate_template_report_data([{'details': normalized}])
    return {'highlight': report['highlights'][0], 'recommendations': report['recommendations']}


def _deterministic_final(item_results, report_language='en'):
    records = [
        {
            'title': item['highlight'].get('title'),
            'code': item['highlight'].get('code'),
            'severity': item['highlight'].get('severity'),
            'summary': item['highlight'].get('summary'),
            'affected': item['highlight'].get('affected'),
            'references': item['highlight'].get('references'),
            'table': item['highlight'].get('table'),
            'recommendations': item.get('recommendations'),
        }
        for item in item_results
    ]
    executive_summary, trends, recommendations = _deterministic_report_sections(records)
    return {
        'title': _fixed_report_title(report_language),
        'executive_summary': executive_summary,
        'trends': trends,
        'recommendations': recommendations,
    }


def _assemble_report(final_data, item_results, report_language='en'):
    report = dict(final_data)
    report['highlights'] = [item['highlight'] for item in item_results]
    report['title'] = _fixed_report_title(report_language)
    validate(instance=report, schema=REPORT_SCHEMA)
    return report


def _render_job_html(job, report, relative_path=None, report_language=None):
    report_language = report_language or job.get(
        'effective_report_language',
        job.get('report_language', 'en'),
    )
    if report_language not in REPORT_LANGUAGES:
        report_language = 'en'
    raw_mode = job.get('effective_generation_mode', job.get('generation_mode'))
    if raw_mode:
        generation_mode = LEGACY_GENERATION_MODES.get(raw_mode, raw_mode)
    elif report.get('template_mode'):
        generation_mode = 'template'
    else:
        generation_mode = 'enriched_weekly'
    if generation_mode == 'enriched_weekly':
        return render_template(
            ENRICHED_REPORT_TEMPLATE,
            report=report,
            generated_at=datetime.now(timezone.utc),
            source_count=job['source_count'],
            report_language=report_language,
            html_language=HTML_LANGUAGE_CODES[report_language],
            labels=ENRICHED_REPORT_LABELS[report_language],
        )
    return render_template(
        REPORT_TEMPLATE,
        report=report,
        generated_at=datetime.now(timezone.utc),
        source_count=job['source_count'],
        report_language=report_language,
        html_language=HTML_LANGUAGE_CODES[report_language],
        labels=REPORT_LABELS[report_language],
    )


def _find_completed_translation_job(source_job_id, language):
    return _job_collection().find_one({
        'input_source': 'translation',
        'translated_from_job_id': source_job_id,
        'report_language': language,
        'status': 'completed',
    })


def _translation_html_for_job(job, language):
    if language not in TRANSLATION_LANGUAGES:
        return None
    if job.get('input_source') == 'translation' and job.get('report_language') == language:
        if job.get('status') == 'completed' and job.get('html'):
            return job['html']
        return None
    translation_job = _find_completed_translation_job(job['_id'], language)
    if translation_job and translation_job.get('html'):
        return translation_job['html']
    return None


def _store_translation_html(translation_job, translated_report, language):
    render_context = {
        **translation_job,
        'status': 'completed',
        'source_count': translation_job.get('source_count', 0),
    }
    return _render_job_html(
        render_context,
        translated_report,
        report_language=language,
    )


def _job_is_cancelled(job_object_id):
    job = _job_collection().find_one({'_id': job_object_id}, {'status': 1})
    return job is not None and job.get('status') == 'cancelled'


def cancel_job(job_id):
    try:
        job_object_id = ObjectId(job_id)
    except Exception as exc:
        raise ValueError('Invalid report job id.') from exc
    result = _job_collection().update_one(
        {'_id': job_object_id, 'status': {'$in': ['queued', 'running']}},
        {'$set': {
            'status': 'cancelled',
            'updated_at': datetime.now(timezone.utc),
        }},
    )
    if result.matched_count == 0:
        raise ValueError('Report job cannot be cancelled.')
    return str(job_object_id)


def delete_job(job_id):
    try:
        job_object_id = ObjectId(job_id)
    except Exception as exc:
        raise ValueError('Invalid report job id.') from exc
    job = _job_collection().find_one({'_id': job_object_id}, {'status': 1})
    if job is None:
        raise ValueError('Report job not found.')
    if job.get('status') in ('queued', 'running'):
        raise ValueError('Cancel the report job before deleting it.')
    _result_collection().delete_many({'job_id': job_object_id})
    _input_collection().delete_many({'job_id': job_object_id})
    try:
        from enriched_report.pipeline_collections import purge_run_artifacts
        purge_run_artifacts(get_web_database(), str(job_object_id))
    except Exception:
        pass
    _job_collection().delete_one({'_id': job_object_id})
    return str(job_object_id)


def _create_translation_job(source_job, language):
    now = datetime.now(timezone.utc)
    generation_mode = LEGACY_GENERATION_MODES.get(
        source_job.get('effective_generation_mode', source_job.get('generation_mode', 'enriched_weekly')),
        source_job.get('effective_generation_mode', source_job.get('generation_mode', 'enriched_weekly')),
    )
    translation_job = {
        'job_type': 'translation',
        'input_source': 'translation',
        'translated_from_job_id': source_job['_id'],
        'generation_mode': generation_mode,
        'effective_generation_mode': generation_mode,
        'report_language': language,
        'effective_report_language': language,
        'source_count': source_job.get('source_count', 0),
        'processed_count': 0,
        'current_position': 0,
        'item_fallback_count': 0,
        'status': 'queued',
        'created_at': now,
        'updated_at': now,
        'provider': 'llama-server',
        'model': f'Translation ({REPORT_LANGUAGES[language]})',
        'progress_percent': 0,
        'progress_current': 0,
        'progress_total': 1,
        'progress_label': 'Queued',
        'status_message': None,
        'estimated_seconds_remaining': None,
        'started_at': None,
        'pipeline_logs': [],
    }
    return _job_collection().insert_one(translation_job).inserted_id


def _translation_report_for_job(job, language):
    if language == 'en':
        return job.get('report')
    if job.get('input_source') == 'translation' and job.get('report_language') == language:
        if job.get('status') == 'completed' and job.get('report'):
            return job['report']
    translation = (job.get('translations') or {}).get(language) or {}
    if translation.get('status') == 'completed' and translation.get('report'):
        return translation['report']
    return None


def _find_active_translation_job(source_job_id, language):
    return _job_collection().find_one({
        'input_source': 'translation',
        'translated_from_job_id': source_job_id,
        'report_language': language,
        'status': {'$in': ['queued', 'running']},
    })


def request_report_translation(app, source_job_id, language):
    if language not in TRANSLATION_LANGUAGES:
        raise ValueError('Translation language must be "zh" or "ch".')
    try:
        source_job_object_id = ObjectId(source_job_id)
    except Exception as exc:
        raise ValueError('Invalid report job id.') from exc
    source_job = _job_collection().find_one({'_id': source_job_object_id})
    if source_job is None:
        raise ValueError('Report job not found.')
    if source_job.get('input_source') == 'translation':
        raise ValueError('Translate the original English report, not a translation job.')
    if source_job.get('status') != 'completed' or not source_job.get('report'):
        raise ValueError('Only completed reports can be translated.')

    existing = _find_active_translation_job(source_job_object_id, language)
    if existing is not None:
        return {
            'id': str(existing['_id']),
            'source_id': str(source_job_object_id),
            'language': language,
            'status': existing['status'],
        }

    translation_job_id = _create_translation_job(source_job, language)
    thread = threading.Thread(
        target=run_report_translation,
        args=(app, str(translation_job_id)),
        daemon=True,
    )
    thread.start()
    return {
        'id': str(translation_job_id),
        'source_id': str(source_job_object_id),
        'language': language,
        'status': 'queued',
    }


def run_report_translation(app, translation_job_id, client=None):
    with app.app_context():
        translation_job_object_id = ObjectId(translation_job_id)
        collection = _job_collection()
        try:
            translation_job = collection.find_one({'_id': translation_job_object_id})
            if translation_job is None:
                return
            if translation_job.get('input_source') != 'translation':
                raise ValueError('Translation runner received a non-translation job.')
            if translation_job.get('status') not in ('queued', 'running'):
                return
            language = translation_job.get('report_language')
            if language not in TRANSLATION_LANGUAGES:
                raise ValueError('Translation language must be "zh" or "ch".')

            source_job = collection.find_one({'_id': translation_job['translated_from_job_id']})
            if source_job is None or source_job.get('status') != 'completed' or not source_job.get('report'):
                raise ValueError('Source report is no longer available for translation.')

            generation_mode = LEGACY_GENERATION_MODES.get(
                translation_job.get('effective_generation_mode', translation_job.get('generation_mode', 'enriched_weekly')),
                translation_job.get('effective_generation_mode', translation_job.get('generation_mode', 'enriched_weekly')),
            )
            mark_job_started(translation_job_id)
            collection.update_one(
                {'_id': translation_job_object_id},
                {'$set': {
                    'status': 'running',
                    'progress_current': 0,
                    'progress_total': 1,
                    'progress_percent': 0,
                    'progress_label': 'Starting translation',
                    'updated_at': datetime.now(timezone.utc),
                }},
            )
            append_job_log(translation_job_id, f'Starting {REPORT_LANGUAGES[language]} translation.')

            from enriched_report.translator import translate_report

            def progress_callback(current, total, message):
                update_job_progress(
                    translation_job_id,
                    current=current,
                    total=total,
                    label=message,
                    message=message,
                )
                append_job_log(
                    translation_job_id,
                    f'{REPORT_LANGUAGES[language]} translation: {message}.',
                )

            translated = translate_report(
                source_job['report'],
                generation_mode,
                language,
                app.config,
                client=client,
                progress_callback=progress_callback,
            )
            if generation_mode != 'enriched_weekly':
                validate(instance=translated, schema=REPORT_SCHEMA)
            now = datetime.now(timezone.utc)
            rendered_html = _store_translation_html(translation_job, translated, language)
            collection.update_one(
                {'_id': translation_job_object_id},
                {'$set': {
                    'status': 'completed',
                    'report': translated,
                    'html': rendered_html,
                    'html_updated_at': now,
                    'processed_count': translation_job.get('source_count', 0),
                    'current_position': translation_job.get('source_count', 0),
                    'progress_current': 1,
                    'progress_total': 1,
                    'progress_percent': 100,
                    'progress_label': 'Completed',
                    'estimated_seconds_remaining': 0,
                    'completed_at': now,
                    'updated_at': now,
                    'error': '',
                },
                '$unset': {'html_path': ''}},
            )
            append_job_log(translation_job_id, f'{REPORT_LANGUAGES[language]} translation completed.')
        except Exception as exc:
            failed_language = (translation_job or {}).get('report_language', 'translation')
            collection.update_one(
                {'_id': translation_job_object_id, 'status': {'$ne': 'cancelled'}},
                {'$set': {
                    'status': 'failed',
                    'error': str(exc),
                    'progress_label': 'Translation failed',
                    'updated_at': datetime.now(timezone.utc),
                }},
            )
            append_job_log(
                translation_job_id,
                f'{REPORT_LANGUAGES.get(failed_language, failed_language)} translation failed: {exc}',
            )


def run_template_job(app, job_id):
    with app.app_context():
        collection = _job_collection()
        job_object_id = ObjectId(job_id)
        try:
            job = collection.find_one({'_id': job_object_id})
            if job is None or job.get('status') == 'cancelled':
                return
            if job.get('status') not in ('queued', 'running'):
                return
            raw_mode = job.get('generation_mode', 'enriched_weekly')
            if LEGACY_GENERATION_MODES.get(raw_mode, raw_mode) != 'template':
                raise ValueError('Independent template runner received a non-template job.')
            mark_job_started(job_id)
            if job.get('status') == 'queued':
                collection.update_one(
                    {'_id': job_object_id, 'status': 'queued'},
                    {'$set': {'status': 'running', 'updated_at': datetime.now(timezone.utc)}},
                )

            inputs = list(_input_collection().find({'job_id': job_object_id}).sort('position', 1))
            init_job_progress(
                job_id,
                total_units=max(len(inputs), 1),
                label='Loading sources',
                message='Loading template report sources.',
            )
            records = []
            for position, item in enumerate(inputs, start=1):
                if _job_is_cancelled(job_object_id):
                    return
                details = compact_details(_load_input_details(item), current_app.config)
                normalized = next(iter(details.values()), details) if len(details) == 1 else details
                records.append({**_source_record_for_item(item), 'details': normalized})
                update_job_progress(
                    job_id,
                    current=position,
                    label=f'Loading source {position}/{len(inputs)}',
                    message=f'Loaded source {position}/{len(inputs)}.',
                )
            if _job_is_cancelled(job_object_id):
                return

            append_job_log(job_id, 'Building fixed template report.')
            update_job_progress(
                job_id,
                current=len(inputs),
                label='Building report',
                message='Building fixed template report.',
            )
            report = generate_template_report_data(records)
            collection.update_one(
                {'_id': job_object_id, 'status': {'$ne': 'cancelled'}},
                {'$set': {
                    'status': 'completed',
                    'processed_count': len(inputs),
                    'current_position': len(inputs),
                    'report': report,
                    'progress_percent': 100,
                    'progress_current': len(inputs),
                    'progress_total': max(len(inputs), 1),
                    'progress_label': 'Completed',
                    'estimated_seconds_remaining': 0,
                    'completed_at': datetime.now(timezone.utc),
                    'updated_at': datetime.now(timezone.utc),
                }},
            )
            append_job_log(job_id, 'Fixed template report completed.')
        except Exception as exc:
            if _job_is_cancelled(job_object_id):
                return
            collection.update_one(
                {'_id': job_object_id, 'status': {'$nin': ['cancelled']}},
                {'$set': {
                    'status': 'failed',
                    'updated_at': datetime.now(timezone.utc),
                    'error': str(exc),
                }},
            )
        finally:
            _input_collection().delete_many({'job_id': job_object_id})


def run_job(app, job_id):
    with app.app_context():
        job = _job_collection().find_one(
            {'_id': ObjectId(job_id)},
            {'generation_mode': 1, 'input_source': 1},
        )
        if job is not None and job.get('input_source') == 'translation':
            run_report_translation(app, job_id)
            return
        raw_mode = (job or {}).get('generation_mode', 'enriched_weekly')
        generation_mode = LEGACY_GENERATION_MODES.get(raw_mode, raw_mode)
        if generation_mode == 'template':
            run_template_job(app, job_id)
            return
        if generation_mode == 'enriched_weekly':
            from enriched_report.orchestrator import run_enriched_pipeline
            run_enriched_pipeline(app, job_id)
            return
        _job_collection().update_one(
            {'_id': ObjectId(job_id), 'status': {'$nin': ['cancelled', 'completed', 'failed']}},
            {'$set': {
                'status': 'failed',
                'updated_at': datetime.now(timezone.utc),
                'error': f'Unsupported generation mode: {raw_mode}',
            }},
        )


def start_job(app, job_id):
    thread = threading.Thread(target=run_job, args=(app, job_id), daemon=True)
    thread.start()

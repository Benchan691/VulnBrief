import re

from jsonschema import validate


class SectionParseError(ValueError):
    pass


_LABEL_LINE_PATTERN = re.compile(r'^([A-Za-z][A-Za-z0-9_ ]*):\s*([^\n]*)$', re.MULTILINE)
_BULLET_PATTERN = re.compile(r'^[-*]\s+', re.MULTILINE)


def _strip_bullet(line):
    return _BULLET_PATTERN.sub('', line).strip()


def _normalize_label(label):
    cleaned = str(label or '').strip().strip('*_`')
    return re.sub(r'\s+', '_', cleaned.upper())


def _split_labels(text):
    cleaned = (text or '').strip()
    if not cleaned:
        return {}
    matches = list(_LABEL_LINE_PATTERN.finditer(cleaned))
    if not matches:
        raise SectionParseError('Response is missing labeled sections.')
    blocks = {}
    for index, match in enumerate(matches):
        label = _normalize_label(match.group(1))
        inline = match.group(2).strip()
        block_start = match.end()
        if block_start < len(cleaned) and cleaned[block_start] == '\n':
            block_start += 1
        end = matches[index + 1].start() if index + 1 < len(matches) else len(cleaned)
        body = cleaned[block_start:end].strip()
        if inline:
            body = f'{inline}\n{body}'.strip() if body else inline
        blocks[label] = body
    return blocks


def _parse_list_block(block):
    if not block or block.upper() == 'NONE':
        return []
    items = []
    for line in block.splitlines():
        stripped = _strip_bullet(line.strip())
        if stripped:
            items.append(stripped)
    return items


def _parse_string_block(block, field_name):
    if not block:
        raise SectionParseError(f'Missing required content for {field_name}.')
    return block.strip()


def parse_labeled_section(text, spec, optional_labels=None):
    optional_labels = optional_labels or set()
    blocks = _split_labels(text)
    result = {}
    for label, field_name, is_list in spec:
        block = blocks.get(label)
        if block is None:
            if label in optional_labels and is_list:
                result[field_name] = []
                continue
            raise SectionParseError(f'Missing required label: {label}')
        if is_list:
            result[field_name] = _parse_list_block(block)
        else:
            result[field_name] = _parse_string_block(block, field_name)
    return result


def parse_executive_summary(text):
    return parse_labeled_section(text, [
        ('SUMMARY', 'summary', False),
        ('KEY_FINDINGS', 'key_findings', True),
    ], optional_labels={'KEY_FINDINGS'})


def parse_research_scope(text):
    return parse_labeled_section(text, [
        ('SUMMARY', 'summary', False),
        ('CRITERIA', 'criteria', True),
    ])


def parse_weekly_risk_trend(text):
    return parse_labeled_section(text, [
        ('SUMMARY', 'summary', False),
        ('TREND_POINTS', 'trend_points', True),
    ])


def parse_management_brief(text):
    return parse_labeled_section(text, [
        ('SUMMARY', 'summary', False),
        ('BUSINESS_IMPACT', 'business_impact', False),
        ('DECISIONS_NEEDED', 'decisions_needed', True),
    ])


def _parse_remediation_action(line, line_number):
    parts = [part.strip() for part in line.split('|')]
    if len(parts) != 3:
        raise SectionParseError(
            f'Invalid action line {line_number}: expected "priority | action | CVE-1, CVE-2".',
        )
    priority, action, cve_part = parts
    if not priority or not action:
        raise SectionParseError(f'Invalid action line {line_number}: priority and action are required.')
    cve_ids = [item.strip() for item in cve_part.split(',') if item.strip()]
    if not cve_ids:
        raise SectionParseError(f'Invalid action line {line_number}: at least one CVE ID is required.')
    return {
        'priority': priority,
        'action': action,
        'cve_ids': cve_ids,
    }


def parse_remediation_playbook(text):
    blocks = _split_labels(text)
    summary = blocks.get('SUMMARY')
    actions_block = blocks.get('ACTIONS')
    if summary is None:
        raise SectionParseError('Missing required label: SUMMARY')
    if actions_block is None:
        raise SectionParseError('Missing required label: ACTIONS')
    actions = []
    if actions_block.upper() != 'NONE':
        for line_number, line in enumerate(actions_block.splitlines(), start=1):
            stripped = _strip_bullet(line.strip())
            if stripped:
                actions.append(_parse_remediation_action(stripped, line_number))
    return {
        'summary': _parse_string_block(summary, 'summary'),
        'actions': actions,
    }


def parse_unsupported_claims(text):
    blocks = _split_labels(text)
    block = blocks.get('UNSUPPORTED_CLAIMS')
    if block is None:
        raise SectionParseError('Missing required label: UNSUPPORTED_CLAIMS')
    return _parse_list_block(block)


SECTION_TEXT_PARSERS = {
    'executive_summary': parse_executive_summary,
    'research_scope': parse_research_scope,
    'weekly_risk_trend': parse_weekly_risk_trend,
    'management_brief': parse_management_brief,
    'remediation_playbook': parse_remediation_playbook,
}


SECTION_TEXT_FORMATS = {
    'executive_summary': (
        'SUMMARY:\n'
        '<paragraph>\n\n'
        'KEY_FINDINGS:\n'
        '- <finding>'
    ),
    'research_scope': (
        'SUMMARY:\n'
        '<paragraph>\n\n'
        'CRITERIA:\n'
        '- <criterion>'
    ),
    'weekly_risk_trend': (
        'SUMMARY:\n'
        '<paragraph>\n\n'
        'TREND_POINTS:\n'
        '- <trend point>'
    ),
    'management_brief': (
        'SUMMARY:\n'
        '<paragraph>\n\n'
        'BUSINESS_IMPACT:\n'
        '<paragraph>\n\n'
        'DECISIONS_NEEDED:\n'
        '- <decision>'
    ),
    'remediation_playbook': (
        'SUMMARY:\n'
        '<paragraph>\n\n'
        'ACTIONS:\n'
        '<priority> | <action> | <CVE-1>, <CVE-2>'
    ),
}


def build_vulnerability_detail_table(cards):
    return {
        'rows': [
            {
                'cve_id': card['cve_id'],
                'title': card['title'],
                'vendor': card.get('vendor'),
                'product': card.get('product'),
                'severity': card.get('severity'),
                'priority_score': card['priority_score'],
                'patch_priority': card['patch_priority'],
                'what_happened': card['what_happened'],
                'why_matters': card['why_matters'],
                'how_to_respond': card['how_to_respond'],
                'source_urls': list(card.get('source_references') or []),
            }
            for card in cards
        ],
    }


def build_appendix(cards, evidence_cards, metrics):
    refs_by_cve = {}
    cve_order = []
    seen = set()

    def add_url(cve_id, url):
        if not url:
            return
        key = (cve_id, url)
        if key in seen:
            return
        seen.add(key)
        if cve_id not in refs_by_cve:
            refs_by_cve[cve_id] = []
            cve_order.append(cve_id)
        refs_by_cve[cve_id].append(url)

    for card in cards:
        cve_id = card['cve_id']
        for url in card.get('source_references') or []:
            add_url(cve_id, url)
    for card in evidence_cards:
        add_url(card['cve_id'], card.get('source_url'))

    refs = [
        {'cve_id': cve_id, 'urls': refs_by_cve[cve_id]}
        for cve_id in cve_order
    ]
    appendix_metrics = {
        key: value
        for key, value in metrics.items()
        if key not in {'run_id', '_id'}
    }
    return {
        'source_references': refs,
        'metrics': appendix_metrics,
    }


def parse_section_text(section_name, text):
    parser = SECTION_TEXT_PARSERS.get(section_name)
    if parser is None:
        raise SectionParseError(f'No text parser configured for section: {section_name}')
    return parser(text)


def validate_section(section_name, section, schema):
    validate(instance=section, schema=schema)
    return section

import re

from jsonschema import validate


class CompanyAIParseError(ValueError):
    pass


_LABEL_PATTERN = re.compile(r'^([A-Z][A-Z0-9_]*):\s*$', re.MULTILINE)
_BULLET_PATTERN = re.compile(r'^[-*]\s+', re.MULTILINE)


ITEM_TEXT_FORMAT = (
    'SUMMARY:\n'
    '<evidence-based summary>\n\n'
    'CODE:\n'
    '<CVE or source code, or NONE>\n\n'
    'SEVERITY:\n'
    '<severity, or NONE>\n\n'
    'AFFECTED:\n'
    '- <affected product>\n\n'
    'REFERENCES:\n'
    '- <url>\n\n'
    'RECOMMENDATIONS:\n'
    '- <defensive action>\n\n'
    'TABLE:\n'
    'NONE\n\n'
    'Or for a table:\n'
    'TABLE:\n'
    'CAPTION: <caption>\n'
    'HEADERS: col1 | col2 | col3\n'
    '<cell> | <cell> | <cell>'
)

FINAL_TEXT_FORMAT = (
    'EXECUTIVE_SUMMARY:\n'
    '<paragraph>\n\n'
    'TRENDS:\n'
    '- <trend>\n\n'
    'RECOMMENDATIONS:\n'
    '- <recommendation>'
)


def _strip_bullet(line):
    return _BULLET_PATTERN.sub('', line).strip()


def _split_labels(text):
    cleaned = (text or '').strip()
    if not cleaned:
        return {}
    matches = list(_LABEL_PATTERN.finditer(cleaned))
    if not matches:
        raise CompanyAIParseError('Response is missing labeled sections.')
    blocks = {}
    for index, match in enumerate(matches):
        label = match.group(1)
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(cleaned)
        blocks[label] = cleaned[start:end].strip()
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
        raise CompanyAIParseError(f'Missing required content for {field_name}.')
    return block.strip()


def _optional_string(block):
    if not block or block.upper() == 'NONE':
        return None
    stripped = block.strip()
    return stripped or None


def _parse_table_block(block):
    if not block or block.strip().upper() == 'NONE':
        return None
    caption = None
    headers = []
    rows = []
    header_found = False
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        upper = stripped.upper()
        if upper.startswith('CAPTION:'):
            caption = stripped.split(':', 1)[1].strip() or None
            continue
        if upper.startswith('HEADERS:'):
            headers = [part.strip() for part in stripped.split(':', 1)[1].split('|') if part.strip()]
            header_found = bool(headers)
            continue
        if header_found:
            rows.append([part.strip() for part in stripped.split('|')])
    if not headers or not rows:
        raise CompanyAIParseError('TABLE block requires HEADERS and at least one data row.')
    table = {'headers': headers, 'rows': rows}
    if caption:
        table['caption'] = caption
    return table


def parse_item_text(text):
    blocks = _split_labels(text)
    summary = blocks.get('SUMMARY')
    recommendations_block = blocks.get('RECOMMENDATIONS')
    if summary is None:
        raise CompanyAIParseError('Missing required label: SUMMARY')
    if recommendations_block is None:
        raise CompanyAIParseError('Missing required label: RECOMMENDATIONS')
    highlight = {
        'summary': _parse_string_block(summary, 'SUMMARY'),
    }
    code = _optional_string(blocks.get('CODE'))
    if code is not None:
        highlight['code'] = code
    severity = _optional_string(blocks.get('SEVERITY'))
    if severity is not None:
        highlight['severity'] = severity
    affected = _parse_list_block(blocks.get('AFFECTED'))
    if affected:
        highlight['affected'] = affected
    references = _parse_list_block(blocks.get('REFERENCES'))
    if references:
        highlight['references'] = references
    table = _parse_table_block(blocks.get('TABLE'))
    if table is not None:
        highlight['table'] = table
    return {
        'highlight': highlight,
        'recommendations': _parse_list_block(recommendations_block),
    }


def parse_final_text(text):
    blocks = _split_labels(text)
    summary = blocks.get('EXECUTIVE_SUMMARY')
    trends = blocks.get('TRENDS')
    recommendations = blocks.get('RECOMMENDATIONS')
    if summary is None:
        raise CompanyAIParseError('Missing required label: EXECUTIVE_SUMMARY')
    if trends is None:
        raise CompanyAIParseError('Missing required label: TRENDS')
    if recommendations is None:
        raise CompanyAIParseError('Missing required label: RECOMMENDATIONS')
    return {
        'executive_summary': _parse_string_block(summary, 'EXECUTIVE_SUMMARY'),
        'trends': _parse_list_block(trends),
        'recommendations': _parse_list_block(recommendations),
    }


def item_system_prompt(language):
    return (
        f'Write one cybersecurity vulnerability report item in {language}. '
        'Use only the provided review details. Do not invent facts. Preserve identifiers and URLs. '
        'Do not write a title; the system assigns titles from source metadata. '
        'Include TABLE only when structured comparison is clearer than prose. '
        'Do not return JSON or markdown. '
        f'Use exactly this output format:\n{ITEM_TEXT_FORMAT}'
    )


def final_system_prompt(summary_prompt, language):
    return (
        f'{summary_prompt.strip()}\n\n'
        'Do not return JSON or markdown. '
        f'Use exactly this output format:\n{FINAL_TEXT_FORMAT}'
    )


def validate_parsed_item(item, schema):
    validate(instance=item, schema=schema)
    return item


def validate_parsed_final(final_data, schema):
    validate(instance=final_data, schema=schema)
    return final_data

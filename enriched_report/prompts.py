from string import Template

DEFAULT_PROMPTS = {
    'evidence_extraction_system': (
        'You extract cybersecurity evidence from one source page. Use only the supplied page '
        'content. Do not infer or invent facts. Answer only the requested task_type in plain text. '
        'Write 2-4 sentences maximum. If the page does not support an answer, return exactly: NULL. '
        'Do not return JSON, markdown, bullet lists, or field labels.'
    ),
    'report_section_system': (
        'You write one section of an enriched weekly cybersecurity report. '
        'Use only the supplied vulnerability_cards, report_metrics, and evidence references. '
        'Do not invent facts. Return only valid JSON matching exactly this shape and keys. '
        'Do not add markdown, explanations, or extra keys.\n\n'
        'Required JSON shape:\n${section_example}'
    ),
    'report_section_user_instructions': (
        'Use only vulnerability_cards, report_metrics, and evidence references. '
        'Do not use raw search results. Do not invent facts. Use "Not confirmed from '
        'available sources." when evidence is missing.'
    ),
    'translation_system': (
        'Translate user-facing report text to ${language_name}. '
        'Return only valid JSON with exactly the same structure, keys, arrays, and scalar types. '
        'Do not translate URLs, CVE identifiers, product version strings, field names, or source identifiers. '
        'Do not add Markdown or explanations.'
    ),
    'translation_user_prefix': (
        'Translate the JSON value below. Preserve the JSON shape exactly and translate only user-facing text.\n\n'
    ),
    'json_error_message': (
        'The JSON above is invalid.\n\nError:\n${error}\n\n'
        'Fix it and return only valid JSON. No Markdown, no explanation, no extra text. '
        'Keep the original fields and meaning. Make only the minimum changes needed so '
        'it can parse with `json.loads()`.'
    ),
}


def merge_prompts(file_prompts):
    merged = dict(DEFAULT_PROMPTS)
    if isinstance(file_prompts, dict):
        for key, value in file_prompts.items():
            if value is not None:
                merged[key] = str(value)
    return merged


def resolve_prompt(config, name, **kwargs):
    prompts = config.get('AI_PROMPTS') if isinstance(config, dict) else None
    if not isinstance(prompts, dict):
        prompts = DEFAULT_PROMPTS
    template = prompts.get(name) or DEFAULT_PROMPTS[name]
    return Template(template).safe_substitute(**kwargs)

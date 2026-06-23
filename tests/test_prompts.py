from enriched_report.prompts import DEFAULT_PROMPTS, merge_prompts, resolve_prompt


def test_resolve_prompt_uses_default_when_config_missing():
    text = resolve_prompt({}, 'evidence_extraction_system')
    assert text == DEFAULT_PROMPTS['evidence_extraction_system']


def test_resolve_prompt_substitutes_language_name():
    text = resolve_prompt(
        {'AI_PROMPTS': DEFAULT_PROMPTS},
        'translation_system',
        language_name='Traditional Chinese',
    )
    assert 'Traditional Chinese' in text
    assert '${language_name}' not in text


def test_resolve_prompt_substitutes_section_example():
    text = resolve_prompt(
        {'AI_PROMPTS': DEFAULT_PROMPTS},
        'report_section_system',
        section_example='{"summary": "Example"}',
    )
    assert '{"summary": "Example"}' in text
    assert '${section_example}' not in text


def test_merge_prompts_overrides_defaults():
    merged = merge_prompts({'translation_user_prefix': 'Custom prefix\n\n'})
    assert merged['translation_user_prefix'] == 'Custom prefix\n\n'
    assert merged['evidence_extraction_system'] == DEFAULT_PROMPTS['evidence_extraction_system']


def test_resolve_prompt_uses_config_override():
    config = {
        'AI_PROMPTS': {
            **DEFAULT_PROMPTS,
            'evidence_extraction_system': 'Custom evidence prompt.',
        },
    }
    assert resolve_prompt(config, 'evidence_extraction_system') == 'Custom evidence prompt.'

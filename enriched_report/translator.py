import json
from copy import deepcopy

from jsonschema import ValidationError

from .json_response import extract_json
from .llama_client import EnrichedLlamaClient
from .prompts import resolve_prompt
from .schemas import validate_enriched_report


TRANSLATION_LANGUAGES = {
    'zh': 'Traditional Chinese',
    'ch': 'Simplified Chinese',
}

_PROTECTED_KEYS = {
    'card_anchor',
    'cve_id',
    'cve_ids',
    'code',
    'references',
    'related_links',
    'source_link',
    'source_urls',
    'href',
    'urls',
}


def _system_prompt(language_name, config):
    return resolve_prompt(
        config,
        'translation_system',
        language_name=language_name,
    )


def _fragment_for_translation(fragment):
    if isinstance(fragment, dict):
        return {
            key: _fragment_for_translation(value)
            for key, value in fragment.items()
            if key not in _PROTECTED_KEYS
        }
    if isinstance(fragment, list):
        return [_fragment_for_translation(item) for item in fragment]
    return fragment


def _merge_translation(source, translated):
    if isinstance(source, dict):
        translated_dict = translated if isinstance(translated, dict) else {}
        merged = {}
        for key, value in source.items():
            if key in _PROTECTED_KEYS:
                merged[key] = deepcopy(value)
            elif key in translated_dict:
                merged[key] = _merge_translation(value, translated_dict[key])
            else:
                merged[key] = deepcopy(value)
        for key, value in translated_dict.items():
            if key not in merged:
                merged[key] = deepcopy(value)
        return merged
    if isinstance(source, list):
        translated_list = translated if isinstance(translated, list) else []
        return [
            _merge_translation(source[index], translated_list[index])
            if index < len(translated_list)
            else deepcopy(source[index])
            for index in range(len(source))
        ]
    return translated


def _translate_fragment(fragment, language, client, config):
    language_name = TRANSLATION_LANGUAGES[language]
    translatable = _fragment_for_translation(fragment)
    source_json = json.dumps(translatable, ensure_ascii=False, default=str)
    prompt = resolve_prompt(config, 'translation_user_prefix') + source_json
    raw_text, _ = client.complete_text(
        _system_prompt(language_name, config),
        prompt,
        max_output_tokens=client.report_max_output_tokens,
    )
    translated = extract_json(raw_text)
    translated = _normalize_scalar_translation(translatable, translated)
    translated = _restore_non_string_scalars(translatable, translated)
    _assert_same_shape(translatable, translated)
    merged = _merge_translation(fragment, translated)
    return _restore_protected_values(fragment, merged)


def _normalize_scalar_translation(source, translated):
    if isinstance(source, str):
        if isinstance(translated, str):
            return translated
        if isinstance(translated, dict) and len(translated) == 1:
            only_value = next(iter(translated.values()))
            if isinstance(only_value, str):
                return only_value
    return translated


def _restore_non_string_scalars(source, translated):
    if isinstance(source, dict) and isinstance(translated, dict):
        return {
            key: _restore_non_string_scalars(source[key], translated[key])
            for key in source
        }
    if isinstance(source, list) and isinstance(translated, list):
        return [
            _restore_non_string_scalars(source[index], translated[index])
            for index in range(len(source))
        ]
    if isinstance(source, (bool, int, float)) and not isinstance(source, str):
        return deepcopy(source)
    return translated


def _assert_same_shape(source, translated):
    if isinstance(source, dict):
        if not isinstance(translated, dict) or set(source.keys()) != set(translated.keys()):
            raise ValueError('Translated JSON object keys do not match the source.')
        for key, value in source.items():
            _assert_same_shape(value, translated[key])
        return
    if isinstance(source, list):
        if not isinstance(translated, list) or len(source) != len(translated):
            raise ValueError('Translated JSON array shape does not match the source.')
        for index, value in enumerate(source):
            _assert_same_shape(value, translated[index])
        return
    if source is None:
        if translated is not None:
            raise ValueError('Translated JSON changed a null value.')
        return
    if not isinstance(translated, type(source)):
        raise ValueError('Translated JSON changed scalar types.')


def _restore_protected_values(source, translated, key=None):
    if key in _PROTECTED_KEYS:
        return deepcopy(source)
    if isinstance(source, dict) and isinstance(translated, dict):
        return {
            item_key: _restore_protected_values(source[item_key], translated[item_key], item_key)
            for item_key in source
        }
    if isinstance(source, list) and isinstance(translated, list):
        return [
            _restore_protected_values(source[index], translated[index], key)
            for index in range(len(source))
        ]
    return translated


def _progress(progress_callback, current, total, section_name):
    if progress_callback is not None:
        progress_callback(current, total, f'Translating {section_name}')


def _translate_enriched_report(report, language, client, config, progress_callback=None):
    translated = deepcopy(report)
    translated.pop('weekly_risk_trend', None)
    translated.pop('remediation_playbook', None)
    translated.pop('appendix', None)
    row_count = len((report.get('vulnerability_detail_table') or {}).get('rows') or [])
    section_total = 2 + row_count
    current = 0

    translated['title'] = _translate_fragment(report['title'], language, client, config)
    current += 1
    _progress(progress_callback, current, section_total, 'title')

    translated['executive_summary'] = _translate_fragment(report['executive_summary'], language, client, config)
    current += 1
    _progress(progress_callback, current, section_total, 'executive_summary')

    rows = []
    for index, row in enumerate((report.get('vulnerability_detail_table') or {}).get('rows') or [], start=1):
        rows.append(_translate_fragment(row, language, client, config))
        current += 1
        _progress(progress_callback, current, section_total, f'vulnerability row {index}/{row_count}')
    translated['vulnerability_detail_table'] = {'rows': rows}
    return validate_enriched_report(translated)


def _translate_template_highlight(highlight, language, client, config):
    translated = deepcopy(highlight)
    fragment = {
        'title': highlight.get('title', ''),
        'severity': highlight.get('severity', ''),
        'summary': highlight.get('summary', ''),
        'affected': highlight.get('affected') or [],
        'table': highlight.get('table') or {},
    }
    translated_fragment = _translate_fragment(fragment, language, client, config)
    translated.update(translated_fragment)
    newsletter = highlight.get('newsletter')
    if isinstance(newsletter, dict):
        translated['newsletter'] = _translate_fragment(newsletter, language, client, config)
    return translated


def _translate_template_report(report, language, client, config, progress_callback=None):
    translated = deepcopy(report)
    highlights = report.get('highlights') or []
    section_total = 1 + len(highlights)
    top_fragment = {
        'title': report.get('title', ''),
        'executive_summary': report.get('executive_summary', ''),
        'trends': report.get('trends') or [],
        'recommendations': report.get('recommendations') or [],
    }
    translated.update(_translate_fragment(top_fragment, language, client, config))
    _progress(progress_callback, 1, section_total, 'summary')

    translated_highlights = []
    for index, highlight in enumerate(highlights, start=1):
        translated_highlights.append(_translate_template_highlight(highlight, language, client, config))
        _progress(progress_callback, index + 1, section_total, f'item {index}/{len(highlights)}')
    translated['highlights'] = translated_highlights
    return translated


def translate_report(report, generation_mode, language, config, client=None, progress_callback=None):
    if language not in TRANSLATION_LANGUAGES:
        raise ValueError('Translation language must be "zh" or "ch".')
    client = client or EnrichedLlamaClient(config)
    if generation_mode == 'enriched_weekly':
        return _translate_enriched_report(report, language, client, config, progress_callback)
    return _translate_template_report(report, language, client, config, progress_callback)

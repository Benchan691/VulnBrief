from datetime import datetime, timezone

from bson import ObjectId
from flask import render_template
from jsonschema import validate

from core.database import get_vulnerabilities_database, get_web_database
from reports.template_builder import (
    ENRICHED_REPORT_LABELS,
    ENRICHED_REPORT_TEMPLATE,
    GENERATION_MODES,
    HTML_LANGUAGE_CODES,
    LEGACY_GENERATION_MODES,
    REPORT_LABELS,
    REPORT_LANGUAGES,
    REPORT_SCHEMA,
    REPORT_TEMPLATE,
    TRANSLATION_LANGUAGES,
    _deterministic_report_sections,
    _fixed_report_title,
    generate_template_report_data,
)
from reviews.repository import (
    MAX_EXPORT_SELECTIONS,
    canonical_selection_id,
    resolve_vulnerability_document,
    review_views,
)


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
        provider = 'Search API + llama-server'
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
        from reports.enriched.pipeline_collections import purge_run_artifacts
        purge_run_artifacts(get_web_database(), str(job_object_id))
    except Exception:
        pass
    _job_collection().delete_one({'_id': job_object_id})
    return str(job_object_id)


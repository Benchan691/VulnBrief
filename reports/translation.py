import threading
from datetime import datetime, timezone

from bson import ObjectId
from jsonschema import validate

from reports.jobs import _job_collection, _store_translation_html
from reports.progress import append_job_log, mark_job_started, update_job_progress
from reports.template_builder import (
    LEGACY_GENERATION_MODES,
    REPORT_LANGUAGES,
    REPORT_SCHEMA,
    TRANSLATION_LANGUAGES,
)


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

            from reports.enriched.translator import translate_report

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
                    'status_message': str(exc),
                    'progress_label': 'Translation failed',
                    'updated_at': datetime.now(timezone.utc),
                }},
            )
            append_job_log(
                translation_job_id,
                f'{REPORT_LANGUAGES.get(failed_language, failed_language)} translation failed: {exc}',
            )

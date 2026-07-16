import threading
from datetime import datetime, timezone

from bson import ObjectId
from flask import current_app

from reports.jobs import _input_collection, _job_collection, _job_is_cancelled, _load_input_details
from reports.progress import append_job_log, init_job_progress, mark_job_started, update_job_progress
from reports.template_builder import (
    LEGACY_GENERATION_MODES,
    compact_details,
    generate_template_report_data,
    _source_record_for_item,
)
from reports.translation import run_report_translation


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
                    'status_message': str(exc),
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
            from reports.enriched.orchestrator import run_enriched_pipeline
            run_enriched_pipeline(app, job_id)
            return
        _job_collection().update_one(
            {'_id': ObjectId(job_id), 'status': {'$nin': ['cancelled', 'completed', 'failed']}},
            {'$set': {
                'status': 'failed',
                'updated_at': datetime.now(timezone.utc),
                'error': f'Unsupported generation mode: {raw_mode}',
                'status_message': f'Unsupported generation mode: {raw_mode}',
            }},
        )


def start_job(app, job_id):
    thread = threading.Thread(target=run_job, args=(app, job_id), daemon=True)
    thread.start()

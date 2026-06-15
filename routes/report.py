import json
from bson import ObjectId, json_util
from flask import Response, current_app, jsonify, render_template, request
from pymongo.errors import PyMongoError

from mongo import get_web_database
from report_harness import (
    _assemble_report,
    _deterministic_final,
    _render_job_html,
    cancel_job,
    create_job,
    resolve_review_selections,
    start_job,
)
from . import report_blueprint
from .common import login_required


def _jobs():
    return get_web_database()['report_jobs']


def _serialize_job(job):
    job = dict(job)
    legacy_fields = ('html', 'html_updated_at', 'html_path')
    if job.get('_id') is not None and any(field in job for field in legacy_fields):
        _jobs().update_one(
            {'_id': job['_id']},
            {'$unset': {field: '' for field in legacy_fields}},
        )
    job['id'] = str(job.pop('_id'))
    job.setdefault('generation_mode', 'company_ai')
    job.setdefault('effective_generation_mode', job['generation_mode'])
    job.setdefault('report_language', 'en')
    job.setdefault('effective_report_language', job['report_language'])
    job.pop('records', None)
    job.pop('company_ai_conversation_id', None)
    job.pop('html', None)
    job.pop('html_updated_at', None)
    job.pop('html_path', None)
    job.pop('report', None)
    return json_util.loads(json_util.dumps(job))


def _get_job(job_id):
    try:
        return _jobs().find_one({'_id': ObjectId(job_id)})
    except Exception:
        return None


@report_blueprint.route('/reports')
@login_required
def reports():
    return render_template('reports.html')


@report_blueprint.route('/api/reports')
@login_required
def get_report_jobs():
    try:
        jobs = _jobs().find({}).sort('created_at', -1).limit(100)
        return jsonify({'data': [_serialize_job(job) for job in jobs]})
    except PyMongoError:
        return jsonify({'error': 'Unable to load report history.'}), 503


@report_blueprint.route('/api/reports', methods=['POST'])
@login_required
def create_report_job():
    data = request.get_json(silent=True) or {}
    generation_mode = request.form.get('generation_mode') or data.get('generation_mode') or 'company_ai'
    report_language = request.form.get('report_language') or data.get('report_language') or 'en'
    input_source = None
    inputs = None

    try:
        if request.files.get('json_file'):
            input_source = 'upload'
            raw = request.files['json_file'].read()
            if len(raw) > 20 * 1024 * 1024:
                return jsonify({'error': 'Uploaded JSON is limited to 20 MB.'}), 400
            inputs = json_util.loads(raw.decode('utf-8'))
            if not isinstance(inputs, list) or not all(isinstance(item, dict) for item in inputs):
                return jsonify({'error': 'Uploaded JSON must be an array of documents.'}), 400
            if not all(isinstance(item.get('details'), dict) for item in inputs):
                return jsonify({'error': 'Each uploaded document must contain a details object.'}), 400
        else:
            input_source = 'review_selections'
            inputs = resolve_review_selections(data.get('selections'))

        job_id = create_job(inputs, input_source, generation_mode, report_language)
        start_job(current_app._get_current_object(), job_id)
        status = 'running' if generation_mode == 'template' else 'queued'
        return jsonify({'id': job_id, 'status': status}), 202
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to create report job.'}), 503


@report_blueprint.route('/api/reports/<job_id>/cancel', methods=['POST'])
@login_required
def cancel_report_job(job_id):
    try:
        cancel_job(job_id)
        return jsonify({'id': job_id, 'status': 'cancelled'})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to cancel report job.'}), 503


@report_blueprint.route('/api/reports/<job_id>')
@login_required
def get_report_job(job_id):
    try:
        job = _get_job(job_id)
        if job is None:
            return jsonify({'error': 'Report job not found.'}), 404
        return jsonify(_serialize_job(job))
    except PyMongoError:
        return jsonify({'error': 'Unable to load report job.'}), 503


def _send_job_html(job_id, as_attachment):
    job = _get_job(job_id)
    if job is None or (as_attachment and job.get('status') != 'completed'):
        return jsonify({'error': 'Completed report not found.'}), 404
    _jobs().update_one(
        {'_id': job['_id']},
        {'$unset': {'html': '', 'html_updated_at': '', 'html_path': ''}},
    )
    report = job.get('report')
    if report is None and job.get('status') in ('running', 'cancelled'):
        stored_results = list(
            get_web_database()['report_job_results']
            .find({'job_id': job['_id']})
            .sort('position', 1)
        )
        item_results = [
            {
                'highlight': item.get('highlight') or {},
                'recommendations': item.get('recommendations') or [],
            }
            for item in stored_results
        ]
        if item_results:
            language = job.get('effective_report_language', job.get('report_language', 'en'))
            report = _assemble_report(
                _deterministic_final(item_results, language),
                item_results,
                language,
            )
    if report is None:
        return jsonify({'error': 'Completed report not found.'}), 404

    job.setdefault('source_count', len(report.get('highlights') or []))
    job.setdefault('effective_report_language', job.get('report_language', 'en'))
    rendered = _render_job_html(job, report)
    headers = {}
    if as_attachment:
        headers['Content-Disposition'] = f'attachment; filename="report-{job_id}.html"'
    return Response(rendered, content_type='text/html; charset=utf-8', headers=headers)


@report_blueprint.route('/reports/<job_id>/preview')
@login_required
def preview_report(job_id):
    return _send_job_html(job_id, False)


@report_blueprint.route('/reports/<job_id>/download')
@login_required
def download_report(job_id):
    return _send_job_html(job_id, True)

import json
import os

from bson import ObjectId, json_util
from flask import current_app, jsonify, render_template, request, send_from_directory
from pymongo.errors import PyMongoError

from mongo import get_web_database
from report_harness import create_job, resolve_review_selections, start_job
from . import report_blueprint
from .common import login_required


def _jobs():
    return get_web_database()['report_jobs']


def _serialize_job(job):
    job = dict(job)
    job['id'] = str(job.pop('_id'))
    job.setdefault('generation_mode', 'company_ai')
    job.setdefault('effective_generation_mode', job['generation_mode'])
    job.setdefault('report_language', 'en')
    job.setdefault('effective_report_language', job['report_language'])
    job.pop('records', None)
    job.pop('company_ai_conversation_id', None)
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
        return jsonify({'id': job_id, 'status': 'queued'}), 202
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to create report job.'}), 503


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
    if job is None or not job.get('html_path') or (as_attachment and job.get('status') != 'completed'):
        return jsonify({'error': 'Completed report not found.'}), 404

    base = os.path.realpath(current_app.config['NEWSLETTER_ROOT'])
    path = os.path.realpath(os.path.join(base, job['html_path']))
    if not path.startswith(base + os.sep):
        return jsonify({'error': 'Invalid report path.'}), 403
    return send_from_directory(
        os.path.dirname(path),
        os.path.basename(path),
        as_attachment=as_attachment,
    )


@report_blueprint.route('/reports/<job_id>/preview')
@login_required
def preview_report(job_id):
    return _send_job_html(job_id, False)


@report_blueprint.route('/reports/<job_id>/download')
@login_required
def download_report(job_id):
    return _send_job_html(job_id, True)

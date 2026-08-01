from flask import Blueprint, jsonify, render_template, request
from pymongo.errors import PyMongoError

from core.auth import login_required
from core.database import get_vulnerabilities_database, get_web_database
from operations.health import build_health_snapshot
from newsletters.normalizer import render_newsletter
from operations.templates import (
    get_newsletter_template_config,
    latest_newsletter_templates,
    newsletter_editor_rows,
    normalize_template_config,
    save_newsletter_template_config,
)
from core.i18n import t
from reviews.repository import resolve_vulnerability_document


operations_blueprint = Blueprint('operations', __name__)


@operations_blueprint.route('/operations')
@login_required
def operations():
    return render_template('operations/index.html')


@operations_blueprint.route('/api/operations/health')
@login_required
def get_operations_health():
    try:
        return jsonify(build_health_snapshot(get_web_database(), get_vulnerabilities_database()))
    except PyMongoError:
        return jsonify({'error': t('Unable to load scheduler health.')}), 503


@operations_blueprint.route('/api/operations/newsletter-templates')
@login_required
def get_newsletter_templates():
    try:
        return jsonify({'data': latest_newsletter_templates(get_vulnerabilities_database())})
    except PyMongoError:
        return jsonify({'error': t('Unable to load Email Editor.')}), 503


@operations_blueprint.route('/api/operations/newsletter-editor')
@login_required
def get_newsletter_editor():
    try:
        return jsonify({'data': newsletter_editor_rows(
            get_vulnerabilities_database(),
            get_web_database(),
        )})
    except PyMongoError:
        return jsonify({'error': t('Unable to load Email Editor.')}), 503


@operations_blueprint.route('/api/operations/newsletter-editor', methods=['PUT'])
@login_required
def save_newsletter_editor():
    try:
        config = save_newsletter_template_config(
            get_web_database(),
            request.get_json(silent=True) or {},
            get_vulnerabilities_database(),
        )
        return jsonify({'data': config})
    except (TypeError, ValueError) as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': t('Unable to save Email Editor.')}), 503


@operations_blueprint.route('/api/operations/newsletter-editor/preview', methods=['POST'])
@login_required
def preview_newsletter_editor():
    payload = request.get_json(silent=True) or {}
    source_collection = str(payload.get('source_collection') or '').strip()
    selection_id = str(payload.get('selection_id') or '').strip()
    if not source_collection or not selection_id:
        return jsonify({'error': t('A source record is required for preview.')}), 400
    try:
        document = resolve_vulnerability_document(
            get_vulnerabilities_database(), source_collection, selection_id,
        )
        if document is None:
            return jsonify({'error': t('Newsletter source document not found.')}), 404
        config = normalize_template_config(payload.get('config'))
        rendered, newsletter = render_newsletter(document, source_collection, config)
        return jsonify({
            'html': rendered,
            'subject': newsletter.get('subject') or '',
        })
    except PyMongoError:
        return jsonify({'error': t('Unable to render generated newsletter.')}), 503

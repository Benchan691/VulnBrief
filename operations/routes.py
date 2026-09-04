from flask import Blueprint, jsonify, render_template, request
from pymongo.errors import PyMongoError

from core.auth import admin_required, current_user, is_top_admin
from core.database import get_vulnerabilities_database, get_web_database
from operations.health import build_health_snapshot
from newsletters.normalizer import render_newsletter
from operations.templates import (
    get_newsletter_template_config,
    latest_newsletter_templates,
    newsletter_editor_rows,
    normalize_template_config,
    save_newsletter_template_config,
    source_url_rows,
)
from core.i18n import t
from reviews.repository import resolve_vulnerability_document


operations_blueprint = Blueprint('operations', __name__)


@operations_blueprint.route('/operations')
@admin_required
def operations():
    return render_template('operations/index.html')


@operations_blueprint.route('/api/operations/health')
@admin_required
def get_operations_health():
    try:
        user = current_user()
        manager_user_id = None if is_top_admin(user) else user.get('_id')
        return jsonify(build_health_snapshot(
            get_web_database(),
            get_vulnerabilities_database(),
            manager_user_id=manager_user_id,
        ))
    except PyMongoError:
        return jsonify({'error': t('Unable to load scheduler health.')}), 503


@operations_blueprint.route('/api/operations/newsletter-templates')
@admin_required
def get_newsletter_templates():
    try:
        return jsonify({'data': latest_newsletter_templates(get_vulnerabilities_database())})
    except PyMongoError:
        return jsonify({'error': t('Unable to load email templates.')}), 503


@operations_blueprint.route('/api/operations/source-list')
@admin_required
def get_source_list():
    try:
        return jsonify({'data': source_url_rows(get_vulnerabilities_database())})
    except PyMongoError:
        return jsonify({'error': t('Unable to load source URLs.')}), 503


@operations_blueprint.route('/api/operations/newsletter-editor')
@admin_required
def get_newsletter_editor():
    try:
        return jsonify({'data': newsletter_editor_rows(
            get_vulnerabilities_database(),
            get_web_database(),
        )})
    except PyMongoError:
        return jsonify({'error': t('Unable to load email templates.')}), 503


@operations_blueprint.route('/api/operations/newsletter-editor', methods=['PUT'])
@admin_required
def save_newsletter_editor():
    try:
        config = save_newsletter_template_config(get_web_database(), request.get_json(silent=True) or {})
        return jsonify({'data': config})
    except (TypeError, ValueError) as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': t('Unable to save email templates.')}), 503


@operations_blueprint.route('/api/operations/newsletter-editor/preview', methods=['POST'])
@admin_required
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

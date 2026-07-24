from flask import Blueprint, jsonify, render_template
from pymongo.errors import PyMongoError

from core.auth import login_required
from core.database import get_vulnerabilities_database, get_web_database
from operations.health import build_health_snapshot
from operations.templates import latest_newsletter_templates


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
        return jsonify({'error': 'Unable to load scheduler health.'}), 503


@operations_blueprint.route('/api/operations/newsletter-templates')
@login_required
def get_newsletter_templates():
    try:
        return jsonify({'data': latest_newsletter_templates(get_vulnerabilities_database())})
    except PyMongoError:
        return jsonify({'error': 'Unable to load email templates.'}), 503

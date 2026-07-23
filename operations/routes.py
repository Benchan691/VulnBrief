from flask import Blueprint, jsonify, render_template
from pymongo.errors import PyMongoError

from core.auth import login_required
from core.database import get_vulnerabilities_database, get_web_database
from operations.health import build_health_snapshot


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

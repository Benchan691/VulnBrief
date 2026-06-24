from flask import jsonify, render_template, request
from pymongo.errors import PyMongoError

from mongo import get_web_database
from operations_runner import (
    list_runs,
    load_config,
    run_logs,
    save_config,
    start_operation,
    stop_run,
)
from . import operations_blueprint
from .common import login_required


@operations_blueprint.route('/operations')
@login_required
def operations():
    return render_template('operations.html')


@operations_blueprint.route('/api/operations/config')
@login_required
def get_operations_config():
    try:
        return jsonify(load_config(get_web_database()))
    except PyMongoError:
        return jsonify({'error': 'Unable to load operations config.'}), 503


@operations_blueprint.route('/api/operations/config', methods=['PUT'])
@login_required
def update_operations_config():
    try:
        return jsonify(save_config(get_web_database(), request.get_json(silent=True) or {}))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to save operations config.'}), 503


@operations_blueprint.route('/api/operations/runs')
@login_required
def get_operations_runs():
    try:
        return jsonify({'data': list_runs(get_web_database())})
    except PyMongoError:
        return jsonify({'error': 'Unable to load operation runs.'}), 503


@operations_blueprint.route('/api/operations/run/<operation>', methods=['POST'])
@login_required
def run_operation(operation):
    try:
        return jsonify(start_operation(get_web_database(), operation)), 202
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to start operation.'}), 503


@operations_blueprint.route('/api/operations/stop/<run_id>', methods=['POST'])
@login_required
def stop_operation(run_id):
    try:
        return jsonify(stop_run(get_web_database(), run_id))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to stop operation.'}), 503


@operations_blueprint.route('/api/operations/runs/<run_id>/logs')
@login_required
def get_operation_logs(run_id):
    try:
        return jsonify(run_logs(get_web_database(), run_id))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 404
    except PyMongoError:
        return jsonify({'error': 'Unable to load operation logs.'}), 503

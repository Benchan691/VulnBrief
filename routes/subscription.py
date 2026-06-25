from datetime import datetime, timezone

from flask import abort, jsonify, render_template, request
from pymongo.errors import PyMongoError

from mongo import get_vulnerabilities_database
from newsletter_store import filter_newsletter_feed
from subscription_data import (
    get_sub_account_collection,
    normalize_subscription,
    profile_with_window,
    query_profile_matches,
    validate_filters,
    validate_profile,
)
from . import subscription_blueprint
from .common import login_required


def get_collection():
    return get_sub_account_collection()


SCHEDULE_FIELD_UNSET = {
    'schedule_claim_owner': '',
    'schedule_claim_until': '',
    'report_profile.schedule_enabled': '',
    'report_profile.cron': '',
    'report_profile.next_run_at': '',
    'report_profile.last_run_at': '',
    'report_profile.last_job_id': '',
    'report_profile.last_error': '',
    'report_profile.last_match_count': '',
}
TOP_LEVEL_SCHEDULE_FIELD_UNSET = {
    key: value for key, value in SCHEDULE_FIELD_UNSET.items() if '.' not in key
}


def _public_subscription(database, document):
    normalized = normalize_subscription(database, document)
    normalized.pop('_id', None)
    normalized.pop('schedule_claim_until', None)
    normalized.pop('schedule_claim_owner', None)
    return normalized


def _profiles(database, data):
    newsletter_value = data.get('newsletter_profile')
    report_value = data.get('report_profile')
    if report_value is None and 'subscriptions' in data:
        report_value = {'enabled': True, 'filters': {'collections': data.get('subscriptions')}}
    newsletter_profile = validate_profile(database, newsletter_value, 'newsletter')
    report_profile = validate_profile(database, report_value, 'report')
    return newsletter_profile, report_profile


@subscription_blueprint.route('/subscriptions')
@login_required
def subscriptions():
    return render_template('subscriptions.html')


@subscription_blueprint.route('/subscriptions/<path:email>/newsletter-feed')
@login_required
def newsletter_feed(email):
    try:
        database = get_vulnerabilities_database()
        raw = get_collection().find_one({'email': email})
        if raw is None:
            abort(404)
        subscription = normalize_subscription(database, raw)
        saved_filters = subscription['newsletter_profile']['filters']
    except (PyMongoError, ValueError):
        abort(503)
    return render_template('newsletter_feed.html', email=email, saved_filters=saved_filters)


@subscription_blueprint.route('/api/subscriptions')
@login_required
def get_subscriptions():
    try:
        database = get_vulnerabilities_database()
        data = [_public_subscription(database, item) for item in get_collection().find({})]
        return jsonify({'data': data})
    except (PyMongoError, ValueError):
        return jsonify({'error': 'Unable to load subscriptions.'}), 503


@subscription_blueprint.route('/api/subscriptions', methods=['POST'])
@login_required
def add_subscription():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip()
    team = (data.get('team') or '').strip()
    if not email or not team:
        return jsonify({'error': 'Email and team are required.'}), 400
    try:
        database = get_vulnerabilities_database()
        newsletter_profile, report_profile = _profiles(database, data)
        if get_collection().find_one({'email': email}):
            return jsonify({'error': 'A subscription already exists for this email.'}), 409
        now = datetime.now(timezone.utc)
        get_collection().insert_one({
            'email': email,
            'team': team,
            'newsletter_profile': newsletter_profile,
            'report_profile': report_profile,
            'created_at': now,
            'updated_at': now,
        })
        get_collection().update_one({'email': email}, {'$unset': SCHEDULE_FIELD_UNSET})
        return jsonify({'success': True}), 201
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to add subscription.'}), 503


@subscription_blueprint.route('/api/subscriptions/<path:email>', methods=['PUT'])
@login_required
def edit_subscription(email):
    data = request.get_json(silent=True) or {}
    try:
        database = get_vulnerabilities_database()
        existing = get_collection().find_one({'email': email})
        if existing is None:
            return jsonify({'error': 'Subscription not found.'}), 404
        current = normalize_subscription(database, existing)
        data.setdefault('newsletter_profile', current['newsletter_profile'])
        if 'report_profile' not in data and 'subscriptions' not in data:
            data['report_profile'] = current['report_profile']
        newsletter_profile, report_profile = _profiles(database, data)
        update = {
            'newsletter_profile': newsletter_profile,
            'report_profile': report_profile,
            'updated_at': datetime.now(timezone.utc),
        }
        if (data.get('team') or '').strip():
            update['team'] = data['team'].strip()
        get_collection().update_one(
            {'email': email},
            {'$set': update, '$unset': {'subscriptions': '', **TOP_LEVEL_SCHEDULE_FIELD_UNSET}},
        )
        return jsonify({'success': True})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to update subscription.'}), 503


@subscription_blueprint.route('/api/subscriptions/<path:email>', methods=['DELETE'])
@login_required
def remove_subscription(email):
    try:
        result = get_collection().delete_one({'email': email})
        if not result.deleted_count:
            return jsonify({'error': 'Subscription not found.'}), 404
        return jsonify({'success': True})
    except PyMongoError:
        return jsonify({'error': 'Unable to remove subscription.'}), 503


@subscription_blueprint.route('/api/subscriptions/<path:email>/run', methods=['POST'])
@login_required
def run_subscription(email):
    data = request.get_json(silent=True) or {}
    try:
        database = get_vulnerabilities_database()
        raw = get_collection().find_one({'email': email})
        if raw is None:
            return jsonify({'error': 'Subscription not found.'}), 404
        subscription = normalize_subscription(database, raw)
        if not subscription['report_profile']['enabled']:
            return jsonify({'error': 'Report profile is disabled.'}), 400
        profile = profile_with_window(subscription['report_profile'], data)
        profile = validate_profile(database, profile, 'report')
        matches = query_profile_matches(database, profile)
        return jsonify({
            'selections': [
                {'collection': item['collection'], 'selection_id': item['selection_id']}
                for item in matches
            ],
            'count': len(matches),
        })
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to run subscription.'}), 503


@subscription_blueprint.route('/api/subscriptions/<path:email>/newsletters/query', methods=['POST'])
@login_required
def query_newsletter_feed(email):
    data = request.get_json(silent=True) or {}
    try:
        database = get_vulnerabilities_database()
        raw = get_collection().find_one({'email': email})
        if raw is None:
            return jsonify({'error': 'Subscription not found.'}), 404
        subscription = normalize_subscription(database, raw)
        if not subscription['newsletter_profile']['enabled']:
            return jsonify({'error': 'Newsletter feed is disabled for this subscription.'}), 400
        filters = validate_filters(database, data.get('filters'))
        items, count = filter_newsletter_feed(database, email, filters)
        return jsonify({'data': items, 'count': count})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to load newsletter feed.'}), 503

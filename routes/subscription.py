from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from flask import jsonify, render_template, request
from pymongo.errors import PyMongoError

from mongo import get_vulnerabilities_database, get_web_database
from review_data import MAX_EXPORT_SELECTIONS, review_views
from . import subscription_blueprint
from .common import login_required


HONG_KONG = ZoneInfo('Asia/Hong_Kong')
VALID_BOUNDARIES = {'yesterday_00', 'today_00', 'week_ago_00', 'now'}
VALID_WINDOWS = {'daily', 'week', 'custom'}


def get_collection():
    return get_web_database()['subscriptions']


def _validated_subscriptions(database, subscriptions):
    if not isinstance(subscriptions, list):
        return None
    views = review_views(database)
    if any(not isinstance(name, str) or name not in views for name in subscriptions):
        return None
    return list(dict.fromkeys(subscriptions))


def _boundary_times(now=None):
    now = (now or datetime.now(HONG_KONG)).astimezone(HONG_KONG)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return {
        'yesterday_00': today - timedelta(days=1),
        'today_00': today,
        'week_ago_00': today - timedelta(days=7),
        'now': now,
    }


def _utc_iso(value):
    return value.astimezone(timezone.utc).isoformat()


def _parse_hk_datetime(value):
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=HONG_KONG)
    return parsed.astimezone(HONG_KONG)


def _resolve_run_window(data):
    window = data.get('window')
    if window in VALID_WINDOWS:
        boundaries = _boundary_times()
        if window == 'daily':
            return boundaries['today_00'], boundaries['now']
        if window == 'week':
            return boundaries['week_ago_00'], boundaries['now']
        start = _parse_hk_datetime(data.get('start'))
        end = _parse_hk_datetime(data.get('end'))
        if start is None or end is None:
            raise ValueError('Custom window requires valid start and end times.')
        return start, end

    start_name = data.get('start')
    end_name = data.get('end')
    if start_name not in VALID_BOUNDARIES or end_name not in VALID_BOUNDARIES:
        raise ValueError('Invalid time window.')
    boundaries = _boundary_times()
    return boundaries[start_name], boundaries[end_name]


@subscription_blueprint.route('/subscriptions')
@login_required
def subscriptions():
    return render_template('subscriptions.html')


@subscription_blueprint.route('/api/subscriptions')
@login_required
def get_subscriptions():
    try:
        data = list(get_collection().find({}, {'_id': 0}))
        return jsonify({'data': data})
    except PyMongoError:
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
        subscriptions_list = _validated_subscriptions(
            get_vulnerabilities_database(),
            data.get('subscriptions'),
        )
        if subscriptions_list is None:
            return jsonify({'error': 'Subscription list contains an invalid review collection.'}), 400
        if get_collection().find_one({'email': email}):
            return jsonify({'error': 'A subscription already exists for this email.'}), 409
        get_collection().insert_one({
            'email': email,
            'team': team,
            'subscriptions': subscriptions_list,
        })
        return jsonify({'success': True}), 201
    except PyMongoError:
        return jsonify({'error': 'Unable to add subscription.'}), 503


@subscription_blueprint.route('/api/subscriptions/<path:email>', methods=['PUT'])
@login_required
def edit_subscription(email):
    data = request.get_json(silent=True) or {}
    try:
        subscriptions_list = _validated_subscriptions(
            get_vulnerabilities_database(),
            data.get('subscriptions'),
        )
        if subscriptions_list is None:
            return jsonify({'error': 'Subscription list contains an invalid review collection.'}), 400
        result = get_collection().update_one(
            {'email': email},
            {'$set': {'subscriptions': subscriptions_list}},
        )
        if not result.matched_count:
            return jsonify({'error': 'Subscription not found.'}), 404
        return jsonify({'success': True})
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
        start, end = _resolve_run_window(data)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    if start >= end:
        return jsonify({'error': 'Start time must be earlier than end time.'}), 400

    try:
        subscription = get_collection().find_one({'email': email}, {'_id': 0})
        if subscription is None:
            return jsonify({'error': 'Subscription not found.'}), 404

        database = get_vulnerabilities_database()
        views = review_views(database)
        subscribed = _validated_subscriptions(database, subscription.get('subscriptions'))
        if subscribed is None:
            return jsonify({'error': 'Subscription list contains an invalid review collection.'}), 400

        selections = []
        mongo_filter = {
            'scraped_at': {
                '$gte': _utc_iso(start),
                '$lt': _utc_iso(end),
            },
        }
        for collection_name in subscribed:
            source_name = views[collection_name]['options']['viewOn']
            for document in database[source_name].find(
                mongo_filter,
                {'_id': 1},
            ).sort('scraped_at', 1):
                selections.append({
                    'collection': collection_name,
                    'selection_id': str(document['_id']),
                })
                if len(selections) > MAX_EXPORT_SELECTIONS:
                    return jsonify({
                        'error': f'Run result exceeds the {MAX_EXPORT_SELECTIONS}-document limit.',
                    }), 400

        return jsonify({
            'selections': selections,
            'count': len(selections),
            'start': start.isoformat(),
            'end': end.isoformat(),
        })
    except PyMongoError:
        return jsonify({'error': 'Unable to run subscription.'}), 503

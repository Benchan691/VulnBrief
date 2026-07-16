from datetime import datetime, timezone

from flask import Blueprint, abort, current_app, jsonify, render_template, request
from pymongo.errors import PyMongoError

from core.auth import login_required
from core.database import get_vulnerabilities_database
from integrations.email import Mailer
from newsletters.feed import filter_newsletter_feed
from reviews.scoring import rank_scored_selections, score_review_document
from subscriptions.profiles import (
    get_sub_account_collection,
    normalize_subscription,
    profile_with_window,
    validate_filters,
    validate_profile,
)
from subscriptions.query import (
    count_profile_matches,
    query_profile_matches,
)
from subscriptions.scheduler import (
    newsletter_delivery_statistics,
    next_weekly_run,
    render_newsletter_statistics_html,
)


subscription_blueprint = Blueprint('subscription', __name__)

REPORT_PREVIEW_SAMPLE_LIMIT = 25


def get_collection():
    return get_sub_account_collection()


SCHEDULE_FIELD_UNSET = {
    'schedule_claim_owner': '',
    'schedule_claim_until': '',
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


def _with_next_run(profile):
    if profile.get('schedule_enabled'):
        profile = dict(profile)
        profile['next_run_at'] = next_weekly_run(profile)
    return profile


def _report_preview(matches, count=None):
    scored = []
    for item in matches:
        document = item.get('document') or {}
        scored.append({
            **item,
            **score_review_document(document),
        })
    top_cves = [
        item.get('cve_id') or item.get('selection_id')
        for item in rank_scored_selections(scored, 3)
        if item.get('cve_id') or item.get('selection_id')
    ]
    return {
        'count': len(matches) if count is None else count,
        'top_cves': top_cves,
    }


@subscription_blueprint.route('/subscriptions')
@login_required
def subscriptions():
    return render_template('subscriptions/index.html')


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
    return render_template('newsletters/feed.html', email=email, saved_filters=saved_filters)


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
        report_profile = _with_next_run(report_profile)
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
        newsletter_value = data.get('newsletter_profile')
        if isinstance(newsletter_value, dict) and 'delivery_cursor' not in newsletter_value:
            newsletter_value = {
                **newsletter_value,
                'delivery_cursor': current['newsletter_profile'].get('delivery_cursor') or '',
            }
            data['newsletter_profile'] = newsletter_value
        newsletter_profile, report_profile = _profiles(database, data)
        report_profile = _with_next_run(report_profile)
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


@subscription_blueprint.route('/api/subscriptions/report-preview', methods=['POST'])
@login_required
def preview_subscription_report():
    data = request.get_json(silent=True) or {}
    try:
        database = get_vulnerabilities_database()
        profile = validate_profile(database, data.get('report_profile'), 'report')
        profile = profile_with_window(profile, data)
        count = count_profile_matches(database, profile)
        matches = query_profile_matches(
            database,
            profile,
            limit=REPORT_PREVIEW_SAMPLE_LIMIT,
            include_documents=True,
            allow_partial=True,
        )
        return jsonify(_report_preview(matches, count=count))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to preview report profile.'}), 503
    except Exception as exc:
        return jsonify({'error': str(exc) or 'Unable to preview report profile.'}), 500


@subscription_blueprint.route('/api/subscriptions/<path:email>/send-statistic', methods=['POST'])
@login_required
def send_subscription_statistic(email):
    try:
        database = get_vulnerabilities_database()
        raw = get_collection().find_one({'email': email})
        if raw is None:
            return jsonify({'error': 'Subscription not found.'}), 404
        subscription = normalize_subscription(database, raw)
        if not subscription['newsletter_profile']['enabled']:
            return jsonify({'error': 'Newsletter feed is disabled for this subscription.'}), 400
        stats = newsletter_delivery_statistics(email)
        with Mailer(current_app.config) as mailer:
            mailer.send_email(email, {
                'subject': 'Newsletter delivery statistics',
                'html': render_newsletter_statistics_html(stats),
            })
        return jsonify({
            'success': True,
            'message': 'Newsletter statistics email sent.',
            'statistics': stats,
        })
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to send newsletter statistics.'}), 503
    except Exception as exc:
        return jsonify({'error': str(exc)}), 502


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
        filters = validate_filters(database, {
            'collections': (data.get('filters') or {}).get('collections', []),
        })
        items, count = filter_newsletter_feed(database, email, filters)
        return jsonify({'data': items, 'count': count})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to load newsletter feed.'}), 503

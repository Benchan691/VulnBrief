from copy import deepcopy
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

FILTER_LABELS = {
    'search': 'Search',
    'code': 'CVE or identifier',
    'title': 'Title',
    'impact': 'Impact',
    'affected': 'Affected product',
    'source': 'Source',
}


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
    normalized.get('newsletter_profile', {}).pop('cve_delivery_cutoff', None)
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


def _filter_summary(filters):
    parts = []
    collections = filters.get('collections') or []
    if collections:
        parts.append(f"Collections: {', '.join(collections)}")
    else:
        parts.append('Collections: all collections')
    for field, label in FILTER_LABELS.items():
        if filters.get(field):
            parts.append(f'{label}: {filters[field]}')
    if filters.get('status'):
        parts.append(f"Severity: {', '.join(filters['status'])}")
    if filters.get('severity_threshold'):
        parts.append(f"Minimum severity: {filters['severity_threshold']}")
    if filters.get('include_unknown'):
        parts.append('Include unknown severity: yes')
    if filters.get('keywords'):
        parts.append(f"Keywords: {', '.join(filters['keywords'])}")
    if filters.get('time_window') and filters['time_window'] != 'all':
        window = filters['time_window']
        if window == 'custom':
            window = f"custom ({filters.get('start') or 'unspecified'} to {filters.get('end') or 'unspecified'})"
        parts.append(f'Scrape time window: {window}')
    return parts


def _profile_confirmation_summary(name, profile):
    if not profile.get('enabled'):
        return f'{name}: disabled'
    return f"{name}: enabled; {'; '.join(_filter_summary(profile['filters']))}"


def _profile_notification_card(name, profile):
    enabled = bool(profile.get('enabled'))
    return {
        'name': name,
        'enabled': enabled,
        'status': 'Enabled' if enabled else 'Disabled',
        'summary_lines': _filter_summary(profile['filters']) if enabled else [],
    }


def _subscription_notification_email(kind, subscription, cancellation_url='', changes=None):
    details = {
        'confirmed': {
            'subject': 'Subscription confirmed',
            'badge': 'Confirmed',
            'heading': 'Your subscription is active',
            'intro': 'We will send updates that match the preferences below.',
            'footer': 'You are receiving this email because a Security Portal subscription was created for you.',
        },
        'updated': {
            'subject': 'Subscription updated',
            'badge': 'Updated',
            'heading': 'Your subscription has been updated',
            'intro': 'Your latest notification preferences are shown below.',
            'footer': 'You are receiving this email because a Security Portal subscription was updated for you.',
        },
        'cancelled': {
            'subject': 'Subscription cancelled',
            'badge': 'Cancelled',
            'heading': 'Your subscription has been cancelled',
            'intro': 'Future Security Portal newsletter and report deliveries have stopped.',
            'footer': 'This is a confirmation that your Security Portal subscription was cancelled.',
        },
    }[kind]
    cards = [
        _profile_notification_card('Newsletter Feed', subscription['newsletter_profile']),
        _profile_notification_card('Scheduled Report', subscription['report_profile']),
    ]
    summaries = [_profile_confirmation_summary(card['name'], profile) for card, profile in zip(
        cards,
        (subscription['newsletter_profile'], subscription['report_profile']),
    )]
    text_lines = [
        details['heading'] + '.',
        '',
        details['intro'],
    ]
    if changes:
        text_lines.extend(['', 'What changed:', *[f'- {change}' for change in changes]])
    if kind != 'cancelled':
        text_lines.extend(['', 'Current subscription details:', *[f'- {summary}' for summary in summaries]])
    if cancellation_url and kind != 'cancelled':
        text_lines.extend(['', f'Manage or cancel your subscription: {cancellation_url}'])
    text_lines.extend(['', details['footer']])
    return {
        'subject': details['subject'],
        'text': '\n'.join(text_lines),
        'html': render_template(
            'subscriptions/notification_email.html',
            kind=kind,
            details=details,
            cards=cards,
            changes=changes or [],
            cancellation_url=cancellation_url if kind != 'cancelled' else '',
        ),
    }


def subscription_confirmation_email(subscription, cancellation_url):
    return _subscription_notification_email('confirmed', subscription, cancellation_url)


def _admin_profile_settings(profile, profile_type):
    fields = ['enabled', 'filters']
    if profile_type == 'report':
        fields.extend([
            'generation_mode', 'report_language', 'search_prompt',
            'schedule_enabled', 'schedule_weekday', 'schedule_time',
        ])
    return {field: deepcopy(profile.get(field)) for field in fields}


def _subscription_setting_changes(current, updated):
    changes = []
    if current.get('team') != updated.get('team'):
        changes.append('Team')
    current_newsletter = _admin_profile_settings(current['newsletter_profile'], 'newsletter')
    updated_newsletter = _admin_profile_settings(updated['newsletter_profile'], 'newsletter')
    if current_newsletter['enabled'] != updated_newsletter['enabled']:
        changes.append('Newsletter Feed status')
    if current_newsletter['filters'] != updated_newsletter['filters']:
        changes.append('Newsletter Feed filters')
    current_report = _admin_profile_settings(current['report_profile'], 'report')
    updated_report = _admin_profile_settings(updated['report_profile'], 'report')
    if current_report['enabled'] != updated_report['enabled']:
        changes.append('Scheduled Report status')
    if current_report['filters'] != updated_report['filters']:
        changes.append('Scheduled Report filters')
    if any(current_report[field] != updated_report[field] for field in (
        'generation_mode', 'report_language', 'search_prompt',
    )):
        changes.append('Scheduled Report format')
    if any(current_report[field] != updated_report[field] for field in (
        'schedule_enabled', 'schedule_weekday', 'schedule_time',
    )):
        changes.append('Scheduled Report schedule')
    return changes


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
        newsletter_value = data.get('newsletter_profile')
        if isinstance(newsletter_value, dict):
            # The deployment cutoff is maintained by the service, not clients.
            data = {
                **data,
                'newsletter_profile': {
                    key: value
                    for key, value in newsletter_value.items()
                    if key != 'cve_delivery_cutoff'
                },
            }
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
        subscription = {
            'email': email,
            'newsletter_profile': newsletter_profile,
            'report_profile': report_profile,
        }
        try:
            with Mailer(current_app.config) as mailer:
                mailer.send_email(
                    email,
                    subscription_confirmation_email(
                        subscription,
                        current_app.config.get('SUBSCRIPTION_CONFIRMATION_CANCEL_URL', ''),
                    ),
                )
        except Exception:
            current_app.logger.exception(
                'Subscription confirmation email could not be sent to %s.', email,
            )
            return jsonify({
                'error': 'Subscription was saved, but the confirmation email could not be sent.',
            }), 503
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
        if isinstance(newsletter_value, dict):
            newsletter_value = {
                **newsletter_value,
                # This cutoff is set at deployment and must survive ordinary
                # subscription edits, even though it is not sent to the UI.
                'cve_delivery_cutoff': current['newsletter_profile'].get('cve_delivery_cutoff') or '',
            }
            data['newsletter_profile'] = newsletter_value
        newsletter_profile, report_profile = _profiles(database, data)
        report_profile = _with_next_run(report_profile)
        team = (data.get('team') or '').strip() or current.get('team', '')
        updated_subscription = {
            'email': email,
            'team': team,
            'newsletter_profile': newsletter_profile,
            'report_profile': report_profile,
        }
        changes = _subscription_setting_changes(current, updated_subscription)
        update = {
            'newsletter_profile': newsletter_profile,
            'report_profile': report_profile,
            'updated_at': datetime.now(timezone.utc),
        }
        if team != current.get('team', ''):
            update['team'] = team
        get_collection().update_one(
            {'email': email},
            {'$set': update, '$unset': {'subscriptions': '', **TOP_LEVEL_SCHEDULE_FIELD_UNSET}},
        )
        if changes:
            try:
                with Mailer(current_app.config) as mailer:
                    mailer.send_email(
                        email,
                        _subscription_notification_email(
                            'updated',
                            updated_subscription,
                            current_app.config.get('SUBSCRIPTION_CONFIRMATION_CANCEL_URL', ''),
                            changes,
                        ),
                    )
            except Exception:
                current_app.logger.exception(
                    'Subscription update email could not be sent to %s.', email,
                )
                return jsonify({
                    'error': 'Subscription was updated, but the notification email could not be sent.',
                }), 503
        return jsonify({'success': True})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to update subscription.'}), 503


@subscription_blueprint.route('/api/subscriptions/<path:email>', methods=['DELETE'])
@login_required
def remove_subscription(email):
    try:
        database = get_vulnerabilities_database()
        raw = get_collection().find_one({'email': email})
        if raw is None:
            return jsonify({'error': 'Subscription not found.'}), 404
        subscription = normalize_subscription(database, raw)
        result = get_collection().delete_one({'email': email})
        if not result.deleted_count:
            return jsonify({'error': 'Subscription not found.'}), 404
        try:
            with Mailer(current_app.config) as mailer:
                mailer.send_email(
                    email,
                    _subscription_notification_email('cancelled', subscription),
                )
        except Exception:
            current_app.logger.exception(
                'Subscription cancellation email could not be sent to %s.', email,
            )
            return jsonify({
                'error': 'Subscription was cancelled, but the notification email could not be sent.',
            }), 503
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
            'include_unknown': True,
        })
        filters['keyword'] = str((data.get('filters') or {}).get('keyword') or '').strip()
        items, count = filter_newsletter_feed(database, email, filters)
        return jsonify({'data': items, 'count': count})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': 'Unable to load newsletter feed.'}), 503

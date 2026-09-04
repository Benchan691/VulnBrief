from copy import deepcopy
from datetime import datetime, timezone
import re

from bson import ObjectId
from flask import Blueprint, Response, current_app, jsonify, render_template, request
from pymongo.errors import PyMongoError

from auth.store import (
    MAX_PASSWORD_LENGTH,
    ensure_subscription_user,
    find_user,
    find_user_by_email,
    find_user_by_id,
    normalize_login,
    normalize_username,
    validate_password,
)
from core.auth import admin_required, current_user, is_admin, is_top_admin, login_required
from core.database import get_vulnerabilities_database
from integrations.email import (
    DELIVERY_MODES,
    Mailer,
    send_to_recipients,
)
from reviews.scoring import rank_scored_selections, score_review_document
from subscriptions.profiles import (
    DEFAULT_DELIVERY_MODE,
    get_sub_account_collection,
    normalize_subscription,
    profile_with_window,
    subscription_schema,
    validate_profile,
)
from subscriptions.query import (
    preview_profile_matches,
    query_profile_matches,
)
from subscriptions.vendor_products import MAX_CSV_BYTES, parse_vendor_product_csv
from subscriptions.scheduler import (
    newsletter_delivery_statistics,
    next_monthly_statistic_run,
    next_weekly_run,
    render_newsletter_statistics_html,
)
from subscriptions.sources import source_collection_for_review, subscription_review_views
from core.i18n import t


subscription_blueprint = Blueprint('subscription', __name__)

REPORT_PREVIEW_SAMPLE_LIMIT = 25
MAX_RECIPIENTS = 50
EMAIL_PATTERN = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
VENDOR_PRODUCT_CSV_TEMPLATE = """vendor,product,vendor_aliases,product_aliases
Red Hat,Enterprise Linux,"Red Hat, Inc.|RedHat",RHEL|Red Hat Enterprise Linux
Microsoft,Windows Server,Microsoft Corporation,Windows Server 2019|Windows Server 2022
Apache Software Foundation,HTTP Server,Apache|ASF,Apache HTTPD|httpd
"""

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


def _normalize_recipients(value):
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ValueError('Email recipients must be an array.')
    if not value:
        raise ValueError('At least one email recipient is required.')
    if len(value) > MAX_RECIPIENTS:
        raise ValueError(f'No more than {MAX_RECIPIENTS} email recipients are allowed.')
    recipients = []
    seen = set()
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError('Email recipients must be non-empty text values.')
        email = item.strip().casefold()
        if not EMAIL_PATTERN.fullmatch(email):
            raise ValueError(f'Invalid email address: {item.strip()}')
        if email not in seen:
            recipients.append(email)
            seen.add(email)
    if not recipients:
        raise ValueError('At least one email recipient is required.')
    return recipients


def _recipients_from_data(data, *, required=True):
    if 'emails' in data:
        return _normalize_recipients(data.get('emails'))
    if 'email' in data:
        return _normalize_recipients([data.get('email')])
    if required:
        raise ValueError('At least one email recipient is required.')
    return []


def _normalize_delivery_mode(value):
    value = value or DEFAULT_DELIVERY_MODE
    if not isinstance(value, str) or value not in DELIVERY_MODES:
        raise ValueError('Invalid email delivery mode.')
    return value


def _username_conflict(username, *, exclude_id=None):
    query = {
        'username': {
            '$regex': f'^{re.escape(username)}$',
            '$options': 'i',
        },
    }
    if exclude_id is not None:
        query = {'$and': [query, {'_id': {'$ne': exclude_id}}]}
    return get_collection().find_one(query)


def _identifier_query(identifier):
    identifier = normalize_login(identifier)
    if not identifier:
        return None
    if ObjectId.is_valid(identifier):
        return {'_id': ObjectId(identifier)}
    email = identifier.casefold()
    return {'$or': [{'email': email}, {'emails': email}]}


def _owner_conditions(user):
    if not user:
        return []
    legacy_conditions = []
    username = normalize_username(user.get('username')) if user else ''
    if username:
        legacy_conditions.append({'username': username})
    # Legacy compatibility only. Email is never used by authentication.
    email = normalize_login(user.get('email')) if user else ''
    if email:
        legacy_conditions.extend([
            {'email': email.casefold()},
            {'emails': email.casefold()},
        ])
    if user.get('_id') is None:
        return legacy_conditions
    conditions = [{'owner_user_id': user['_id']}]
    if legacy_conditions:
        conditions.append({
            '$and': [
                {'$or': [
                    {'owner_user_id': {'$exists': False}},
                    {'owner_user_id': None},
                ]},
                {'$or': legacy_conditions},
            ],
        })
    return conditions


def _belongs_to_user(document, user):
    if not user:
        return False
    owner_id = document.get('owner_user_id')
    if owner_id is not None and user.get('_id') is not None:
        return str(owner_id) == str(user['_id'])
    username = normalize_username(document.get('username'))
    if username and username.casefold() == normalize_username(user.get('username')).casefold():
        return True
    email = normalize_login(user.get('email')).casefold()
    recipients = document.get('emails')
    if not isinstance(recipients, list):
        recipients = [document.get('email')]
    return bool(email and email in {
        normalize_login(item).casefold()
        for item in recipients
        if isinstance(item, str) and item.strip()
    })


def _subscription_query(identifier=None):
    user = current_user()
    if is_admin(user):
        scope = {} if is_top_admin(user) else {'managed_by_user_id': user['_id']}
        if identifier is None:
            return scope
        identifier_query = _identifier_query(identifier)
        if identifier_query is None:
            return None
        if scope:
            existing = get_collection().find_one(identifier_query)
            if existing is not None and existing.get('managed_by_user_id') != user['_id']:
                return None
        return identifier_query if not scope else {'$and': [identifier_query, scope]}
    conditions = _owner_conditions(user)
    if identifier is None:
        return {'$or': conditions} if conditions else {'_id': None}
    identifier_query = _identifier_query(identifier)
    if identifier_query is None:
        return None
    existing = get_collection().find_one(identifier_query)
    if existing is not None and not _belongs_to_user(existing, user):
        return None
    if not conditions:
        return {'_id': None}
    return identifier_query if existing is not None else {
        '$and': [identifier_query, {'$or': conditions}],
    }


def _recipient_conflict(recipients, *, exclude_id=None):
    query = {'$or': [
        {
            'emails': {
                '$regex': f'^{re.escape(recipient)}$',
                '$options': 'i',
            },
        }
        for recipient in recipients
    ] + [
        {
            'email': {
                '$regex': f'^{re.escape(recipient)}$',
                '$options': 'i',
            },
        }
        for recipient in recipients
    ]}
    if exclude_id is not None:
        query = {'$and': [query, {'_id': {'$ne': exclude_id}}]}
    return get_collection().find_one(query)


def _delivery_error(result):
    failed = result.get('failed') or []
    if not failed:
        return ''
    return 'Email delivery failed for one or more recipients.'


def _send_subscription_email(subscription, payload):
    with Mailer(current_app.config) as mailer:
        result = send_to_recipients(
            mailer,
            subscription.get('emails') or [subscription.get('email')],
            payload,
            subscription.get('delivery_mode') or DEFAULT_DELIVERY_MODE,
        )
    if result.get('failed'):
        raise RuntimeError(_delivery_error(result))
    return result


def _subscription_access_denied():
    return jsonify({'error': t('You do not have permission to manage this subscription.')}), 403


SCHEDULE_FIELD_UNSET = {
    'schedule_claim_owner': '',
    'schedule_claim_until': '',
}
TOP_LEVEL_SCHEDULE_FIELD_UNSET = {
    key: value for key, value in SCHEDULE_FIELD_UNSET.items() if '.' not in key
}


def _public_subscription(database, document):
    normalized = normalize_subscription(database, document)
    if document.get('_id') is not None:
        normalized['id'] = str(document['_id'])
    normalized.pop('_id', None)
    normalized.pop('owner_user_id', None)
    normalized.pop('managed_by_user_id', None)
    normalized.pop('password', None)
    normalized.pop('password_hash', None)
    normalized.pop('schedule_claim_until', None)
    normalized.pop('schedule_claim_owner', None)
    normalized.pop('statistic_schedule_claim_until', None)
    normalized.pop('statistic_schedule_claim_owner', None)
    normalized.get('newsletter_profile', {}).pop('cve_delivery_cutoff', None)
    return normalized


def _profiles(database, data, *, allow_legacy_report_keywords=False):
    newsletter_value = data.get('newsletter_profile')
    report_value = data.get('report_profile')
    if report_value is None and 'subscriptions' in data:
        report_value = {'enabled': True, 'filters': {'collections': data.get('subscriptions')}}
    newsletter_profile = validate_profile(database, newsletter_value, 'newsletter')
    report_profile = validate_profile(
        database,
        report_value,
        'report',
        allow_legacy_report_keywords=allow_legacy_report_keywords,
    )
    return newsletter_profile, report_profile


def _preview_public_profile(profile):
    profile = deepcopy(profile)
    for field in (
        'delivery_cursor', 'cve_delivery_cutoff',
        'statistic_next_run_at', 'statistic_last_run_at', 'statistic_last_error',
        'next_run_at', 'last_run_at', 'last_job_id', 'last_error', 'last_match_count',
        'legacy_keyword_filter',
    ):
        profile.pop(field, None)
    return profile


def _preview_default_paths(data, *, include_missing_profiles=True):
    paths = []
    for name in ('newsletter_profile', 'report_profile'):
        if name not in data:
            if include_missing_profiles:
                paths.append(name)
            continue
        value = data.get(name)
        if value is None:
            paths.append(name)
            continue
        if not isinstance(value, dict):
            continue
        if 'filters' not in value:
            paths.append(f'{name}.filters')
        elif isinstance(value.get('filters'), dict):
            for field in ('collections', 'search', 'code', 'title', 'impact', 'affected',
                          'status', 'severity_threshold', 'include_unknown', 'source',
                          'keywords', 'vendor_product_filter', 'time_window', 'start',
                          'end', 'source_timestamp', 'report_scope'):
                if field not in value['filters']:
                    paths.append(f'{name}.filters.{field}')
    return paths


def _preview_profiles(database, data):
    mode = data.get('mode')
    if not isinstance(mode, str) or mode not in {'create', 'update'}:
        raise ValueError('Preview mode must be create or update.')

    warnings = []
    applied_defaults = _preview_default_paths(data) if mode == 'create' else []
    if mode == 'create':
        newsletter_value = data.get('newsletter_profile')
        if isinstance(newsletter_value, dict) and 'cve_delivery_cutoff' in newsletter_value:
            data = {
                **data,
                'newsletter_profile': {
                    key: value for key, value in newsletter_value.items()
                    if key != 'cve_delivery_cutoff'
                },
            }
        newsletter_profile, report_profile = _profiles(database, data)
        return newsletter_profile, report_profile, warnings, applied_defaults, None

    identifier = data.get('subscription_id') or data.get('id')
    if identifier is None:
        identifier = data.get('email') or data.get('target_email') or ''
    if not isinstance(identifier, str):
        raise ValueError('Subscription ID must be text when preview mode is update.')
    identifier = identifier.strip()
    if not identifier:
        raise ValueError('Subscription ID is required when preview mode is update.')
    existing = get_collection().find_one(_subscription_query(identifier))
    if existing is None:
        raise LookupError('Subscription not found.')
    current = normalize_subscription(database, existing)
    proposed = dict(data)
    proposed.setdefault('newsletter_profile', current['newsletter_profile'])
    if 'report_profile' not in proposed and 'subscriptions' not in proposed:
        proposed['report_profile'] = current['report_profile']
    newsletter_value = proposed.get('newsletter_profile')
    if isinstance(newsletter_value, dict) and 'delivery_cursor' not in newsletter_value:
        newsletter_value = {
            **newsletter_value,
            'delivery_cursor': current['newsletter_profile'].get('delivery_cursor') or '',
        }
        proposed['newsletter_profile'] = newsletter_value
    if isinstance(newsletter_value, dict):
        proposed['newsletter_profile'] = {
            **newsletter_value,
            'cve_delivery_cutoff': current['newsletter_profile'].get('cve_delivery_cutoff') or '',
        }
    provided_profiles = {
        name: data[name] for name in ('newsletter_profile', 'report_profile') if name in data
    }
    applied_defaults = _preview_default_paths(
        provided_profiles, include_missing_profiles=False,
    )
    current_legacy_keywords = current['report_profile'].get('filters', {}).get('keywords') or []
    newsletter_profile, report_profile = _profiles(
        database,
        proposed,
        allow_legacy_report_keywords=bool(current_legacy_keywords),
    )
    updated_legacy_keywords = report_profile.get('filters', {}).get('keywords') or []
    inventory_enabled = bool(
        report_profile.get('filters', {}).get('vendor_product_filter', {}).get('enabled')
    )
    if (
        current_legacy_keywords
        and updated_legacy_keywords != current_legacy_keywords
        and report_profile.get('enabled')
        and not inventory_enabled
    ):
        raise ValueError(
            'Legacy report keywords cannot be removed from an active profile. '
            'Import a vendor/product CSV to replace them, or disable the report profile.'
        )
    if current_legacy_keywords and report_profile.get('legacy_keyword_filter'):
        warnings.append(
            'The existing legacy report keyword filter is being preserved. '
            'Import a vendor/product CSV to replace it.'
        )
    return newsletter_profile, report_profile, warnings, applied_defaults, identifier


def _with_next_run(profile):
    if profile.get('schedule_enabled'):
        profile = dict(profile)
        profile['next_run_at'] = next_weekly_run(profile)
    return profile


def _with_statistic_next_run(profile):
    if profile.get('statistic_schedule_enabled'):
        profile = dict(profile)
        profile['statistic_next_run_at'] = next_monthly_statistic_run()
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
    vendor_product_filter = filters.get('vendor_product_filter') or {}
    if vendor_product_filter.get('enabled'):
        row_count = len(vendor_product_filter.get('rows') or [])
        parts.append(f'Vendor/product inventory: {row_count} target(s)')
        parts.append(
            'Product-only possible matches: '
            + ('included' if vendor_product_filter.get('include_possible_matches') else 'excluded')
        )
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
    if profile_type == 'newsletter':
        fields.append('statistic_schedule_enabled')
    if profile_type == 'report':
        fields.extend([
            'generation_mode', 'report_language', 'search_prompt',
            'schedule_enabled', 'schedule_weekday', 'schedule_time',
        ])
    return {field: deepcopy(profile.get(field)) for field in fields}


def _subscription_setting_changes(current, updated):
    changes = []
    if current.get('username') != updated.get('username'):
        changes.append('Username')
    if current.get('emails') != updated.get('emails'):
        changes.append('Email recipients')
    if current.get('team') != updated.get('team'):
        changes.append('Team')
    if current.get('delivery_mode') != updated.get('delivery_mode'):
        changes.append('Email delivery mode')
    current_newsletter = _admin_profile_settings(current['newsletter_profile'], 'newsletter')
    updated_newsletter = _admin_profile_settings(updated['newsletter_profile'], 'newsletter')
    if current_newsletter['enabled'] != updated_newsletter['enabled']:
        changes.append('Newsletter Feed status')
    if current_newsletter['filters'] != updated_newsletter['filters']:
        changes.append('Newsletter Feed filters')
    if current_newsletter.get('statistic_schedule_enabled') != updated_newsletter.get('statistic_schedule_enabled'):
        changes.append('Newsletter monthly statistic schedule')
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
    match_examples = []
    for item in matches[:3]:
        match = item.get('vendor_product_match')
        if not match:
            continue
        match_examples.append({
            'cve': item.get('cve_id') or item.get('selection_id'),
            **match,
        })
    return {
        'count': len(matches) if count is None else count,
        'top_cves': top_cves,
        'match_examples': match_examples,
    }


@subscription_blueprint.route('/subscriptions')
@login_required
def subscriptions():
    return render_template('subscriptions/index.html')


@subscription_blueprint.route('/api/subscriptions/vendor-product-template.csv')
@login_required
def vendor_product_template():
    return Response(
        VENDOR_PRODUCT_CSV_TEMPLATE,
        content_type='text/csv; charset=utf-8',
        headers={
            'Content-Disposition': 'attachment; filename="vendor_product_filter_template.csv"',
        },
    )


@subscription_blueprint.route('/api/subscriptions/vendor-product-import', methods=['POST'])
@login_required
def import_vendor_products():
    uploaded = request.files.get('file')
    if uploaded is None or not uploaded.filename:
        return jsonify({'error': t('Choose a vendor/product CSV file.')}), 400
    try:
        payload = uploaded.stream.read(MAX_CSV_BYTES + 1)
        vendor_product_filter, warnings = parse_vendor_product_csv(payload)
        return jsonify({
            'vendor_product_filter': vendor_product_filter,
            'warnings': warnings,
        })
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400


@subscription_blueprint.route('/api/subscriptions')
@login_required
def get_subscriptions():
    try:
        database = get_vulnerabilities_database()
        data = [
            _public_subscription(database, item)
            for item in get_collection().find(_subscription_query())
        ]
        return jsonify({'data': data})
    except (PyMongoError, ValueError):
        return jsonify({'error': t('Unable to load subscriptions.')}), 503


@subscription_blueprint.route('/api/subscriptions/schema')
@login_required
def get_subscription_schema():
    try:
        return jsonify(subscription_schema(get_vulnerabilities_database()))
    except PyMongoError:
        return jsonify({'error': t('Unable to load subscription configuration.')}), 503


@subscription_blueprint.route('/api/subscriptions/collections')
@login_required
def get_subscription_collections():
    try:
        database = get_vulnerabilities_database()
        data = []
        for name, view in sorted(subscription_review_views(database).items()):
            source = source_collection_for_review(name, view)
            if not source:
                continue
            data.append({
                'name': name,
                'source': source,
                'count': database[source].count_documents({}),
            })
        return jsonify({'data': data})
    except PyMongoError:
        return jsonify({'error': t('Unable to load subscription collections.')}), 503


@subscription_blueprint.route('/api/subscriptions/preview', methods=['POST'])
@login_required
def preview_subscription_configuration():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'error': 'Subscription preview must be an object.'}), 400
    if data.get('mode') == 'create' and not is_admin():
        return _subscription_access_denied()
    if data.get('mode') == 'update':
        requested_id = data.get('subscription_id') or data.get('id')
        if requested_id is None:
            requested_id = data.get('email') or data.get('target_email') or ''
        if _subscription_query(requested_id) is None:
            return _subscription_access_denied()
    try:
        database = get_vulnerabilities_database()
        newsletter_profile, report_profile, warnings, applied_defaults, identifier = _preview_profiles(
            database, data,
        )
        normalized_profiles = {
            'newsletter_profile': _preview_public_profile(newsletter_profile),
            'report_profile': _preview_public_profile(report_profile),
        }
        response = {
            'valid': True,
            'mode': data.get('mode'),
            'normalized_profiles': normalized_profiles,
            'newsletter_profile': normalized_profiles['newsletter_profile'],
            'report_profile': normalized_profiles['report_profile'],
            'applied_defaults': applied_defaults,
            'warnings': warnings,
        }
        if identifier:
            response['subscription_id'] = identifier
            if not ObjectId.is_valid(identifier):
                response['email'] = identifier
        return jsonify(response)
    except LookupError:
        return jsonify({'error': t('Subscription not found.')}), 404
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': t('Unable to preview subscription configuration.')}), 503


@subscription_blueprint.route('/api/subscriptions', methods=['POST'])
@admin_required
def add_subscription():
    data = request.get_json(silent=True) or {}
    legacy_email = normalize_login(data.get('email'))
    username = normalize_username(data.get('username')) or legacy_email
    team = normalize_login(data.get('team'))
    try:
        emails = _recipients_from_data(data)
        delivery_mode = _normalize_delivery_mode(data.get('delivery_mode'))
    except ValueError as exc:
        return jsonify({'error': t(str(exc))}), 400
    if not username or not team:
        return jsonify({'error': t('Username, email, and team are required.')}), 400
    password = data.get('password')
    if not isinstance(password, str) or not password:
        return jsonify({'error': t('Password is required.')}), 400
    try:
        validate_password(password)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
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
        newsletter_profile = _with_statistic_next_run(newsletter_profile)
        report_profile = _with_next_run(report_profile)
        if _username_conflict(username):
            return jsonify({'error': t('A subscription already exists for this username.')}), 409
        if _recipient_conflict(emails):
            return jsonify({'error': t('One or more email recipients already belong to another subscription.')}), 409
        existing_user = find_user(username)
        if existing_user is not None:
            active_subscription = get_collection().find_one({
                '$or': [
                    {'owner_user_id': existing_user['_id']},
                    {'username': existing_user.get('username')},
                ],
            })
            if active_subscription is not None:
                return jsonify({'error': t('A subscription already exists for this username.')}), 409
        user = ensure_subscription_user(username, password, email=emails[0])
        now = datetime.now(timezone.utc)
        subscription_document = {
            'owner_user_id': user['_id'],
            'managed_by_user_id': current_user()['_id'],
            'username': username,
            'emails': emails,
            # Keep the first recipient as a compatibility alias for old tools.
            'email': emails[0],
            'team': team,
            'delivery_mode': delivery_mode,
            'newsletter_profile': newsletter_profile,
            'report_profile': report_profile,
            'created_at': now,
            'updated_at': now,
        }
        result = get_collection().insert_one(subscription_document)
        get_collection().update_one({'_id': result.inserted_id}, {'$unset': SCHEDULE_FIELD_UNSET})
        try:
            _send_subscription_email(
                subscription_document,
                subscription_confirmation_email(
                    subscription_document,
                    current_app.config.get('SUBSCRIPTION_CONFIRMATION_CANCEL_URL', ''),
                ),
            )
        except Exception:
            current_app.logger.exception(
                'Subscription confirmation email could not be sent to %s.', emails,
            )
            return jsonify({
                'error': t('Subscription was saved, but the confirmation email could not be sent.'),
            }), 503
        return jsonify({'success': True, 'id': str(result.inserted_id)}), 201
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': t('Unable to add subscription.')}), 503


@subscription_blueprint.route('/api/subscriptions/<path:subscription_id>', methods=['PUT'])
@login_required
def edit_subscription(subscription_id):
    data = request.get_json(silent=True) or {}
    query = _subscription_query(subscription_id)
    if query is None:
        return _subscription_access_denied()
    password = data.get('password')
    if password is not None and not is_admin():
        return jsonify({'error': t('Only an administrator can reset user passwords.')}), 403
    if password is not None and password != '' and (
        not isinstance(password, str) or len(password) > MAX_PASSWORD_LENGTH
    ):
        return jsonify({'error': f'Password must be {MAX_PASSWORD_LENGTH} characters or fewer.'}), 400
    if isinstance(password, str) and password:
        try:
            validate_password(password)
        except ValueError as exc:
            return jsonify({'error': str(exc)}), 400
    try:
        database = get_vulnerabilities_database()
        existing = get_collection().find_one(query)
        if existing is None:
            return jsonify({'error': t('Subscription not found.')}), 404
        current = normalize_subscription(database, existing)
        if not is_admin() and any(field in data for field in ('username', 'emails', 'email', 'password')):
            return jsonify({'error': t('Only an administrator can edit subscription identity fields.')}), 403
        current_user_record = current_user()
        owner_id = current.get('owner_user_id') or (
            current_user_record.get('_id') if current_user_record and not is_admin() else None
        )
        owner = find_user_by_id(owner_id) if owner_id else None
        if owner is None:
            owner = find_user(current.get('username')) if current.get('username') else None
        if owner is None and current.get('email'):
            owner = find_user_by_email(current.get('email'))
        if owner is None and not is_admin():
            owner = current_user_record

        username = normalize_username(data.get('username')) if 'username' in data else (
            current.get('username') or (owner.get('username') if owner else '')
        )
        if not username:
            raise ValueError('Username is required.')
        emails = _recipients_from_data(data) if is_admin() and ('emails' in data or 'email' in data) else current.get('emails')
        emails = _normalize_recipients(emails)
        delivery_mode = _normalize_delivery_mode(
            data['delivery_mode'] if 'delivery_mode' in data else current.get('delivery_mode')
        )
        if is_admin() and _username_conflict(username, exclude_id=existing.get('_id')):
            return jsonify({'error': t('A subscription already exists for this username.')}), 409
        if is_admin() and _recipient_conflict(emails, exclude_id=existing.get('_id')):
            return jsonify({'error': t('One or more email recipients already belong to another subscription.')}), 409
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
        current_legacy_keywords = (
            current['report_profile'].get('filters', {}).get('keywords') or []
        )
        newsletter_profile, report_profile = _profiles(
            database,
            data,
            allow_legacy_report_keywords=bool(current_legacy_keywords),
        )
        updated_legacy_keywords = report_profile.get('filters', {}).get('keywords') or []
        inventory_enabled = bool(
            report_profile.get('filters', {})
            .get('vendor_product_filter', {})
            .get('enabled')
        )
        if (
            current_legacy_keywords
            and updated_legacy_keywords != current_legacy_keywords
            and report_profile.get('enabled')
            and not inventory_enabled
        ):
            raise ValueError(
                'Legacy report keywords cannot be removed from an active profile. '
                'Import a vendor/product CSV to replace them, or disable the report profile.'
        )
        newsletter_profile = _with_statistic_next_run(newsletter_profile)
        report_profile = _with_next_run(report_profile)
        team_value = data.get('team')
        if team_value is not None and not isinstance(team_value, str):
            raise ValueError('Team must be text.')
        team = (team_value or '').strip() or current.get('team', '')
        if not team:
            raise ValueError('Team is required.')
        updated_subscription = {
            'owner_user_id': owner.get('_id') if owner else owner_id,
            'managed_by_user_id': current.get('managed_by_user_id') or (
                current_user_record.get('_id')
                if current_user_record and is_top_admin(current_user_record)
                else None
            ),
            'username': username,
            'emails': emails,
            'email': emails[0],
            'team': team,
            'delivery_mode': delivery_mode,
            'newsletter_profile': newsletter_profile,
            'report_profile': report_profile,
        }
        changes = _subscription_setting_changes(current, updated_subscription)
        update = {
            'owner_user_id': updated_subscription['owner_user_id'],
            'managed_by_user_id': updated_subscription['managed_by_user_id'],
            'username': username,
            'emails': emails,
            'email': emails[0],
            'delivery_mode': delivery_mode,
            'newsletter_profile': newsletter_profile,
            'report_profile': report_profile,
            'updated_at': datetime.now(timezone.utc),
        }
        update['team'] = team
        if is_admin():
            ensure_subscription_user(
                username,
                password if isinstance(password, str) and password else None,
                email=emails[0],
                user_id=owner.get('_id') if owner else owner_id,
            )
        get_collection().update_one(
            query,
            {'$set': update, '$unset': {'subscriptions': '', **TOP_LEVEL_SCHEDULE_FIELD_UNSET}},
        )
        if changes:
            try:
                _send_subscription_email(
                    updated_subscription,
                    _subscription_notification_email(
                        'updated',
                        updated_subscription,
                        current_app.config.get('SUBSCRIPTION_CONFIRMATION_CANCEL_URL', ''),
                        changes,
                    ),
                )
            except Exception:
                current_app.logger.exception(
                    'Subscription update email could not be sent to %s.', emails,
                )
                return jsonify({
                    'error': t('Subscription was updated, but the notification email could not be sent.'),
                }), 503
        return jsonify({'success': True})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': t('Unable to update subscription.')}), 503


@subscription_blueprint.route('/api/subscriptions/<path:subscription_id>', methods=['DELETE'])
@login_required
def remove_subscription(subscription_id):
    query = _subscription_query(subscription_id)
    if query is None:
        return _subscription_access_denied()
    try:
        database = get_vulnerabilities_database()
        raw = get_collection().find_one(query)
        if raw is None:
            return jsonify({'error': t('Subscription not found.')}), 404
        subscription = normalize_subscription(database, raw)
        result = get_collection().delete_one(query)
        if not result.deleted_count:
            return jsonify({'error': t('Subscription not found.')}), 404
        try:
            _send_subscription_email(
                subscription,
                _subscription_notification_email('cancelled', subscription),
            )
        except Exception:
            current_app.logger.exception(
                'Subscription cancellation email could not be sent to %s.', subscription.get('emails'),
            )
            return jsonify({
                'error': t('Subscription was cancelled, but the notification email could not be sent.'),
            }), 503
        return jsonify({'success': True})
    except PyMongoError:
        return jsonify({'error': t('Unable to remove subscription.')}), 503


@subscription_blueprint.route('/api/subscriptions/<path:subscription_id>/run', methods=['POST'])
@login_required
def run_subscription(subscription_id):
    data = request.get_json(silent=True) or {}
    query = _subscription_query(subscription_id)
    if query is None:
        return _subscription_access_denied()
    try:
        database = get_vulnerabilities_database()
        raw = get_collection().find_one(query)
        if raw is None:
            return jsonify({'error': t('Subscription not found.')}), 404
        subscription = normalize_subscription(database, raw)
        if not subscription['report_profile']['enabled']:
            return jsonify({'error': t('Report profile is disabled.')}), 400
        profile = profile_with_window(subscription['report_profile'], data)
        profile = validate_profile(
            database,
            profile,
            'report',
            allow_legacy_report_keywords=bool(profile.get('legacy_keyword_filter')),
        )
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
        return jsonify({'error': t('Unable to run subscription.')}), 503


@subscription_blueprint.route('/api/subscriptions/report-preview', methods=['POST'])
@login_required
def preview_subscription_report():
    data = request.get_json(silent=True) or {}
    requested_id = (
        (data.get('subscription_id') or data.get('id'))
        if isinstance(data, dict) else ''
    )
    if not requested_id and isinstance(data, dict):
        requested_id = data.get('email') or ''
    if not is_admin() or requested_id:
        query = _subscription_query(requested_id)
        if query is None:
            return _subscription_access_denied()
        if requested_id and get_collection().find_one(query) is None:
            return jsonify({'error': t('Subscription not found.')}), 404
    try:
        database = get_vulnerabilities_database()
        profile = validate_profile(database, data.get('report_profile'), 'report')
        profile = profile_with_window(profile, data)
        counts, matches = preview_profile_matches(
            database, profile, REPORT_PREVIEW_SAMPLE_LIMIT,
        )
        preview = _report_preview(matches, count=counts['count'])
        preview.update(counts)
        preview['vendor_product_filter_enabled'] = bool(
            profile['filters'].get('vendor_product_filter', {}).get('enabled')
        )
        return jsonify(preview)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': t('Unable to preview report profile.')}), 503
    except Exception as exc:
        return jsonify({'error': str(exc) or t('Unable to preview report profile.')}), 500


@subscription_blueprint.route('/api/subscriptions/<path:subscription_id>/send-statistic', methods=['POST'])
@login_required
def send_subscription_statistic(subscription_id):
    query = _subscription_query(subscription_id)
    if query is None:
        return _subscription_access_denied()
    try:
        database = get_vulnerabilities_database()
        raw = get_collection().find_one(query)
        if raw is None:
            return jsonify({'error': t('Subscription not found.')}), 404
        subscription = normalize_subscription(database, raw)
        if not subscription['newsletter_profile']['enabled']:
            return jsonify({'error': t('Newsletter feed is disabled for this subscription.')}), 400
        manager_user_id = None if is_top_admin(current_user()) else subscription.get('managed_by_user_id')
        stats = newsletter_delivery_statistics(
            subscription.get('emails') or [subscription.get('email')],
            manager_user_id=manager_user_id,
        )
        _send_subscription_email(subscription, {
                'subject': 'Newsletter delivery statistics',
                'html': render_newsletter_statistics_html(stats),
        })
        return jsonify({
            'success': True,
            'message': t('Newsletter statistics email sent.'),
            'statistics': stats,
        })
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except PyMongoError:
        return jsonify({'error': t('Unable to send newsletter statistics.')}), 503
    except Exception as exc:
        return jsonify({'error': str(exc)}), 502

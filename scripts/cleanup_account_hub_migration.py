#!/usr/bin/env python3
"""Audit and optionally remove records incompatible with Account Hub access.

The command is deliberately dry-run by default.  Applying a plan requires both
``--apply`` and ``--confirm`` and creates a JSON backup before deleting any
document.
"""

import argparse
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from bson import json_util

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from auth.store import (  # noqa: E402
    AUTH_SOURCE_ACCOUNT_HUB,
    AUTH_SOURCE_LOCAL,
    ROLE_ADMIN,
    ROLE_SUB_ADMIN,
    ROLE_USER,
    account_hub_uid_key,
    normalize_username,
    username_key,
    validate_email,
)
from core.bootstrap import BASE_DIR, configure_application  # noqa: E402
from core.database import get_vulnerabilities_database, get_web_database  # noqa: E402
from integrations.email import DELIVERY_MODES  # noqa: E402
from subscriptions.profiles import validate_profile  # noqa: E402


AUTH_COLLECTION = 'auth'
SUB_ACCOUNT_COLLECTION = 'sub_account'
LEGACY_COLLECTIONS = ('subscriptions',)
REPORT_COLLECTIONS = (
    'report_jobs',
    'report_job_inputs',
    'report_job_results',
)
DELIVERY_COLLECTION = 'newsletter_deliveries'
DELETE_ORDER = (
    DELIVERY_COLLECTION,
    'report_job_inputs',
    'report_job_results',
    'report_jobs',
    SUB_ACCOUNT_COLLECTION,
    AUTH_COLLECTION,
    *LEGACY_COLLECTIONS,
)


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _datetime(value):
    return isinstance(value, datetime)


def _id_key(value):
    return str(value) if value is not None else ''


def _candidate(collection, document, reason):
    return {
        'collection': collection,
        '_id': document.get('_id'),
        'reason': reason,
        'document': document,
    }


def _bootstrap_document(document, bootstrap_username):
    """Recognize the reserved row, including a row that needs repair."""
    if username_key(document.get('username')) != username_key(bootstrap_username):
        return False
    source = document.get('auth_source')
    return source in (None, AUTH_SOURCE_LOCAL) and document.get('role') == ROLE_ADMIN


def _auth_reason(document, bootstrap_username):
    """Return ``None`` for a target-shape auth row, otherwise a delete reason."""
    if _bootstrap_document(document, bootstrap_username):
        return None
    username = normalize_username(document.get('username'))
    if not username:
        return 'missing username'
    if username_key(username) == username_key(bootstrap_username):
        return 'username is reserved for the local administrator'
    if document.get('username_key') != username_key(username):
        return 'username_key does not match username'
    if document.get('auth_source') != AUTH_SOURCE_ACCOUNT_HUB:
        return 'non-bootstrap local-auth record'
    if document.get('role') not in {ROLE_USER, ROLE_SUB_ADMIN}:
        return 'Account Hub row has a reserved or invalid role'
    if not isinstance(document.get('disabled'), bool):
        return 'disabled flag is missing or invalid'
    if not isinstance(document.get('pause_managed_subscriptions_when_disabled'), bool):
        return 'subscription pause flag is missing or invalid'
    if document.get('must_change_password') is not False:
        return 'Account Hub row still requires a local password change'
    if not _datetime(document.get('created_at')) or not _datetime(document.get('updated_at')):
        return 'created_at and updated_at must be datetimes'
    if document.get('password') not in (None, ''):
        return 'Account Hub row contains a local password'
    if 'email' in document:
        try:
            validate_email(document.get('email'))
        except ValueError:
            return 'invalid email address'
    if 'account_hub_uid' in document and not account_hub_uid_key(document.get('account_hub_uid')):
        return 'Account Hub UID is empty'
    return None


def _profile_error(database, document):
    if not isinstance(document.get('newsletter_profile'), dict):
        return 'newsletter_profile must be an object'
    if not isinstance(document.get('report_profile'), dict):
        return 'report_profile must be an object'
    try:
        validate_profile(database, document.get('newsletter_profile'), 'newsletter')
        validate_profile(database, document.get('report_profile'), 'report')
    except (TypeError, ValueError) as exc:
        return str(exc)
    return None


def _subscription_emails(document):
    values = document.get('emails')
    if not isinstance(values, list):
        values = [document.get('email')]
    emails = set()
    for value in values:
        try:
            normalized = validate_email(value)
        except ValueError:
            continue
        if normalized:
            emails.add(normalized)
    return emails


def _subscription_reason(document, vulnerability_database, valid_auth_ids):
    if not _text(document.get('username')):
        return 'missing username'
    emails = document.get('emails')
    if not isinstance(emails, list) or not emails:
        return 'emails must be a non-empty list'
    normalized_emails = []
    for value in emails:
        try:
            email = validate_email(value)
        except ValueError as exc:
            return str(exc)
        if not email:
            return 'emails must contain non-empty addresses'
        normalized_emails.append(email)
    if not _text(document.get('email')):
        return 'missing email compatibility field'
    if document.get('email').strip().casefold() != normalized_emails[0]:
        return 'email compatibility field does not match the first recipient'
    if not _text(document.get('team')):
        return 'missing team'
    if document.get('delivery_mode') not in DELIVERY_MODES:
        return 'invalid delivery_mode'
    profile_error = _profile_error(vulnerability_database, document)
    if profile_error:
        return profile_error
    for field in ('owner_user_id', 'managed_by_user_id'):
        value = document.get(field)
        if not value or _id_key(value) not in valid_auth_ids:
            return f'{field} does not reference a preserved auth user'
    return None


def _report_job_reason(document, valid_auth_ids):
    required = ('status', 'input_source', 'created_at', 'updated_at')
    missing = [field for field in required if field not in document]
    if missing:
        return 'missing report job field(s): ' + ', '.join(missing)
    if not _text(document.get('status')) or not _text(document.get('input_source')):
        return 'invalid report job status or input source'
    if not _datetime(document.get('created_at')) or not _datetime(document.get('updated_at')):
        return 'created_at and updated_at must be datetimes'
    manager_id = document.get('managed_by_user_id')
    if not manager_id or _id_key(manager_id) not in valid_auth_ids:
        return 'managed_by_user_id does not reference a preserved auth user'
    return None


def _report_child_reason(document, valid_job_ids):
    job_id = document.get('job_id')
    if not job_id or _id_key(job_id) not in valid_job_ids:
        return 'job_id does not reference a preserved report job'
    return None


def _delivery_reason(
    document,
    valid_auth_ids,
    invalid_subscription_emails=None,
    invalid_subscription_ids=None,
):
    required = ('email', 'database', 'source_collection', 'selection_id', 'sent_at')
    missing = [field for field in required if not _text(document.get(field)) and field != 'sent_at']
    if 'sent_at' not in document or not _datetime(document.get('sent_at')):
        missing.append('sent_at')
    if missing:
        return 'missing delivery field(s): ' + ', '.join(missing)
    email_value = document.get('email')
    if (
        invalid_subscription_emails
        and isinstance(email_value, str)
        and email_value.strip().casefold() in invalid_subscription_emails
    ):
        return 'delivery references a deleted subscription'
    if (
        document.get('subscription_id') is not None
        and invalid_subscription_ids
        and _id_key(document.get('subscription_id')) in invalid_subscription_ids
    ):
        return 'delivery references a deleted subscription'
    manager_id = document.get('managed_by_user_id')
    if not manager_id or _id_key(manager_id) not in valid_auth_ids:
        return 'managed_by_user_id does not reference a preserved auth user'
    return None


def build_cleanup_plan(database, vulnerability_database, bootstrap_username):
    """Return a read-only cleanup plan for the configured web database."""
    bootstrap_username = normalize_username(bootstrap_username)
    if not bootstrap_username:
        raise ValueError('A non-empty bootstrap username is required.')
    candidates = {
        name: [] for name in (
            *LEGACY_COLLECTIONS,
            AUTH_COLLECTION,
            SUB_ACCOUNT_COLLECTION,
            *REPORT_COLLECTIONS,
            DELIVERY_COLLECTION,
        )
    }
    collection_counts = {name: 0 for name in candidates}
    preserved_auth_ids = set()
    invalid_auth_ids = set()
    valid_account_hub_auth = []

    auth_documents = list(database[AUTH_COLLECTION].find({}))
    bootstrap_matches = [
        document for document in auth_documents
        if username_key(document.get('username')) == username_key(bootstrap_username)
    ]
    if len(bootstrap_matches) != 1:
        raise ValueError(
            f'Expected exactly one auth record for bootstrap username {bootstrap_username!r}; '
            f'found {len(bootstrap_matches)}.',
        )
    if not _bootstrap_document(bootstrap_matches[0], bootstrap_username):
        raise ValueError(
            f'Bootstrap username {bootstrap_username!r} is not backed by a local '
            'administrator record; refusing cleanup.',
        )

    invalid_legacy_subscription_ids = set()
    invalid_subscription_emails = set()
    for collection_name in LEGACY_COLLECTIONS:
        for document in database[collection_name].find({}):
            collection_counts[collection_name] += 1
            invalid_legacy_subscription_ids.add(_id_key(document.get('_id')))
            invalid_subscription_emails.update(_subscription_emails(document))
            candidates[collection_name].append(_candidate(
                collection_name,
                document,
                'legacy collection is not part of the target schema',
            ))

    for document in auth_documents:
        collection_counts[AUTH_COLLECTION] += 1
        reason = _auth_reason(document, bootstrap_username)
        if reason is None:
            preserved_auth_ids.add(_id_key(document.get('_id')))
            if document.get('auth_source') == AUTH_SOURCE_ACCOUNT_HUB:
                valid_account_hub_auth.append(document)
        else:
            invalid_auth_ids.add(_id_key(document.get('_id')))
            candidates[AUTH_COLLECTION].append(_candidate(AUTH_COLLECTION, document, reason))

    # The runtime index enforces unique Hub UIDs, and username lookup must be
    # unambiguous as well.  Keep the first valid row and remove later
    # duplicates with their dependent records.
    for field, label, normalizer in (
        ('account_hub_uid', 'Account Hub UID', account_hub_uid_key),
        ('username_key', 'username', username_key),
    ):
        seen = set()
        for document in valid_account_hub_auth:
            value = normalizer(document.get(field))
            if not value or value in seen:
                if value:
                    document_id = _id_key(document.get('_id'))
                    preserved_auth_ids.discard(document_id)
                    invalid_auth_ids.add(document_id)
                    candidates[AUTH_COLLECTION].append(_candidate(
                        AUTH_COLLECTION,
                        document,
                        f'duplicate {label} in Account Hub records',
                    ))
                continue
            seen.add(value)

    subscription_documents = list(database[SUB_ACCOUNT_COLLECTION].find({}))
    valid_subscription_emails = set()
    for document in subscription_documents:
        collection_counts[SUB_ACCOUNT_COLLECTION] += 1
        reason = _subscription_reason(document, vulnerability_database, preserved_auth_ids)
        if reason is not None:
            candidates[SUB_ACCOUNT_COLLECTION].append(_candidate(
                SUB_ACCOUNT_COLLECTION,
                document,
                reason,
            ))
            invalid_subscription_emails.update(_subscription_emails(document))
        else:
            valid_subscription_emails.update(_subscription_emails(document))

    invalid_subscription_emails -= valid_subscription_emails

    invalid_subscription_ids = {
        _id_key(item['_id']) for item in candidates[SUB_ACCOUNT_COLLECTION]
    }

    valid_job_ids = set()
    for document in database['report_jobs'].find({}):
        collection_counts['report_jobs'] += 1
        reason = _report_job_reason(document, preserved_auth_ids)
        if reason is None:
            valid_job_ids.add(_id_key(document.get('_id')))
        else:
            candidates['report_jobs'].append(_candidate('report_jobs', document, reason))

    invalid_job_ids = {
        _id_key(item['_id']) for item in candidates['report_jobs']
    }
    for collection_name in ('report_job_inputs', 'report_job_results'):
        for document in database[collection_name].find({}):
            collection_counts[collection_name] += 1
            reason = _report_child_reason(document, valid_job_ids)
            if reason is None and _id_key(document.get('job_id')) in invalid_job_ids:
                reason = 'parent report job is incompatible'
            if reason is not None:
                candidates[collection_name].append(_candidate(collection_name, document, reason))

    for document in database[DELIVERY_COLLECTION].find({}):
        collection_counts[DELIVERY_COLLECTION] += 1
        reason = _delivery_reason(
            document,
            preserved_auth_ids,
            invalid_subscription_emails,
            invalid_subscription_ids | invalid_legacy_subscription_ids,
        )
        if reason is not None:
            candidates[DELIVERY_COLLECTION].append(_candidate(
                DELIVERY_COLLECTION,
                document,
                reason,
            ))

    # Any ownership link to a removed auth/subscription row is invalid even if
    # the document otherwise has the correct shape.
    for collection_name in ('report_jobs', DELIVERY_COLLECTION):
        for item in list(candidates[collection_name]):
            document = item['document']
            if _id_key(document.get('managed_by_user_id')) in invalid_auth_ids:
                item['reason'] = 'managed_by_user_id references a deleted auth record'
    for item in list(candidates[SUB_ACCOUNT_COLLECTION]):
        document = item['document']
        if (
            _id_key(document.get('owner_user_id')) in invalid_auth_ids
            or _id_key(document.get('managed_by_user_id')) in invalid_auth_ids
        ):
            item['reason'] = 'subscription ownership references a deleted auth record'

    return {
        'bootstrap_username': bootstrap_username,
        'preserved_auth_ids': preserved_auth_ids,
        'invalid_auth_ids': invalid_auth_ids,
        'invalid_subscription_ids': invalid_subscription_ids,
        'invalid_legacy_subscription_ids': invalid_legacy_subscription_ids,
        'invalid_subscription_emails': invalid_subscription_emails,
        'valid_subscription_emails': valid_subscription_emails,
        'valid_job_ids': valid_job_ids,
        'collection_counts': collection_counts,
        'preserved_counts': {
            name: collection_counts[name] - len(candidates[name])
            for name in collection_counts
        },
        'candidates': candidates,
    }


def _orphaned_count(plan):
    return sum(
        1
        for items in plan['candidates'].values()
        for item in items
        if any(token in item['reason'] for token in (
            'references a deleted',
            'parent report job',
            'deleted subscription',
        ))
    )


def write_backup(plan, backup_dir):
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(backup_dir, 0o700)
    payload = {
        'created_at': datetime.now(timezone.utc),
        'bootstrap_username': plan['bootstrap_username'],
        'candidates': plan['candidates'],
    }
    backup_path = backup_dir / 'deletions.json'
    backup_path.write_text(
        json_util.dumps(payload, indent=2),
        encoding='utf-8',
    )
    os.chmod(backup_path, 0o600)
    return backup_path


def apply_cleanup(database, plan, backup_dir):
    """Back up candidates and delete them in dependency-first order."""
    backup_path = write_backup(plan, backup_dir)
    deleted = Counter()
    for collection_name in DELETE_ORDER:
        items = plan['candidates'].get(collection_name) or []
        ids = [item['_id'] for item in items if item.get('_id') is not None]
        if not ids:
            continue
        result = database[collection_name].delete_many({'_id': {'$in': ids}})
        deleted[collection_name] = result.deleted_count
    return backup_path, deleted


def _print_plan(plan):
    print(f"Bootstrap preserved: {plan['bootstrap_username']!r}")
    total = 0
    for collection_name in DELETE_ORDER:
        items = plan['candidates'].get(collection_name) or []
        count = len(items)
        if not count:
            continue
        total += count
        print(f'  {collection_name}: {count} candidate(s)')
        for item in items:
            identifier = _id_key(item.get('_id')) or '<missing _id>'
            print(f"    - {identifier}: {item['reason']}")
    preserved = plan.get('preserved_counts') or {}
    print(
        'Preserved records: '
        + ', '.join(f'{name}={count}' for name, count in preserved.items())
    )
    print(f'Orphaned/dependent candidates: {_orphaned_count(plan)}')
    print(f'Total deletion candidates: {total}')
    if not total:
        print('No incompatible records found.')


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Audit and clean records incompatible with Account Hub access.',
    )
    parser.add_argument(
        '--bootstrap-username',
        help='Reserved local administrator username (overrides application config).',
    )
    parser.add_argument(
        '--apply',
        action='store_true',
        help='Apply the cleanup after creating a backup.',
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Audit only without changing MongoDB (the default).',
    )
    parser.add_argument(
        '--confirm',
        action='store_true',
        help='Required together with --apply; confirms destructive deletion.',
    )
    parser.add_argument(
        '--backup-dir',
        type=Path,
        help='Empty directory to create for the deletion backup.',
    )
    args = parser.parse_args(argv)
    if args.apply and args.dry_run:
        parser.error('--apply and --dry-run cannot be combined')
    if args.confirm and not args.apply:
        parser.error('--confirm requires --apply')
    if args.apply and not args.confirm:
        parser.error('--apply requires --confirm')

    config = configure_application(BASE_DIR)
    configured_bootstrap = (
        args.bootstrap_username
        if args.bootstrap_username is not None
        else config.get('WEB_AUTH_BOOTSTRAP_USERNAME')
    )
    bootstrap_username = normalize_username(configured_bootstrap)
    if not bootstrap_username:
        parser.error('A bootstrap username is required via --bootstrap-username or configuration.')

    database = get_web_database()
    vulnerability_database = get_vulnerabilities_database()
    try:
        plan = build_cleanup_plan(database, vulnerability_database, bootstrap_username)
    except ValueError as exc:
        parser.error(str(exc))
    _print_plan(plan)

    if not args.apply:
        print('Dry run only; no database changes were made.')
        return 0
    if not any(plan['candidates'].values()):
        print('Nothing to delete; no backup was created.')
        print('Final cleanup summary:')
        print(f'  Preserved auth records: {len(plan["preserved_auth_ids"])}')
        print('  Backed up candidates: 0')
        print('  Deleted: none')
        print(f'  Orphaned/dependent candidates: {_orphaned_count(plan)}')
        return 0

    backup_dir = args.backup_dir
    if backup_dir is None:
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        backup_dir = Path(BASE_DIR) / '.account_hub_cleanup' / timestamp
    try:
        backup_path, deleted = apply_cleanup(database, plan, backup_dir)
    except (OSError, TypeError, ValueError) as exc:
        parser.error(f'Cleanup aborted before deletion: {exc}')
    backed_up = sum(len(items) for items in plan['candidates'].values())
    print('Final cleanup summary:')
    print(f'  Preserved auth records: {len(plan["preserved_auth_ids"])}')
    print(f'  Backed up candidates: {backed_up}')
    print(f'  Backup written to: {backup_path}')
    deleted_summary = ', '.join(
        f'{name}={count}' for name, count in deleted.items() if count
    ) or 'none'
    print('  Deleted: ' + deleted_summary)
    print(f'  Orphaned/dependent candidates: {_orphaned_count(plan)}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""One-time utility to migrate legacy subscription documents to newsletter/report profiles."""
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from bson import json_util

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.bootstrap import BASE_DIR, configure_application
from core.database import get_config, get_vulnerabilities_database
from reviews.repository import review_views
from subscriptions.profiles import get_sub_account_collection, validate_profile


LEGACY_ALIASES = {
    'huawei': 'huawei_sa',
    'ransome': 'ransomwarelive',
}


def build_view_indexes(views, review_view_suffix):
    by_source = {}
    by_name = {}
    for name, view in views.items():
        by_name[name] = name
        source = view.get('options', {}).get('viewOn')
        if source:
            by_source[source] = name
        candidate = name[:-len(review_view_suffix)] if name.endswith(review_view_suffix) else None
        if candidate and candidate not in by_source:
            by_source[candidate] = name
    return by_source, by_name


def resolve_legacy_collection(name, by_source, by_name, review_view_suffix):
    if not isinstance(name, str) or not name.strip():
        return None
    name = name.strip()
    if name in by_name:
        return by_name[name]
    if name in by_source:
        return by_source[name]
    aliased = LEGACY_ALIASES.get(name, name)
    if aliased in by_source:
        return by_source[aliased]
    candidate = f'{name}{review_view_suffix}'
    if candidate in by_name:
        return candidate
    aliased_candidate = f'{aliased}{review_view_suffix}'
    if aliased_candidate in by_name:
        return by_name[aliased_candidate]
    return None


def map_legacy_collections(legacy_names, by_source, by_name, review_view_suffix):
    mapped = []
    warnings = []
    seen = set()
    for legacy_name in legacy_names or []:
        view_name = resolve_legacy_collection(
            legacy_name, by_source, by_name, review_view_suffix,
        )
        if view_name is None:
            warnings.append(legacy_name)
            continue
        if view_name not in seen:
            seen.add(view_name)
            mapped.append(view_name)
    return mapped, warnings


def is_already_migrated(document):
    return (
        isinstance(document.get('newsletter_profile'), dict)
        and isinstance(document.get('report_profile'), dict)
    )


def build_profiles(database, legacy_record, mapped_collections):
    newsletter_profile = validate_profile(database, {
        'enabled': bool(legacy_record.get('enabled', True)),
        'filters': {'collections': mapped_collections},
    }, 'newsletter')
    report_profile = validate_profile(database, {
        'enabled': False,
        'filters': {'collections': mapped_collections},
        'generation_mode': 'template',
        'report_language': 'en',
    }, 'report')
    report_profile['enabled'] = False
    return newsletter_profile, report_profile


def migrate_record(database, legacy_record, by_source, by_name, review_view_suffix):
    email = (legacy_record.get('email') or '').strip()
    team = (legacy_record.get('team') or '').strip()
    if not email or not team:
        raise ValueError('Email and team are required.')
    mapped_collections, warnings = map_legacy_collections(
        legacy_record.get('subscriptions', []),
        by_source,
        by_name,
        review_view_suffix,
    )
    newsletter_profile, report_profile = build_profiles(
        database, legacy_record, mapped_collections,
    )
    return {
        'email': email,
        'team': team,
        'newsletter_profile': newsletter_profile,
        'report_profile': report_profile,
        'warnings': warnings,
        '_id': legacy_record.get('_id'),
    }


def load_legacy_records(path):
    payload = json_util.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(payload, list):
        raise ValueError('Input JSON must be an array of subscription documents.')
    return payload


def main():
    parser = argparse.ArgumentParser(
        description='Migrate legacy subscription documents to newsletter/report profiles.',
    )
    parser.add_argument('--input', required=True, help='Path to legacy subscriptions JSON export.')
    parser.add_argument('--dry-run', action='store_true', help='Print actions without writing to MongoDB.')
    parser.add_argument('--yes', action='store_true', help='Apply changes without interactive confirmation.')
    parser.add_argument(
        '--force',
        action='store_true',
        help='Re-migrate subscriptions that already have newsletter/report profiles.',
    )
    args = parser.parse_args()

    configure_application(BASE_DIR)
    config = get_config()
    vuln_db = get_vulnerabilities_database()
    collection = get_sub_account_collection()
    views = review_views(vuln_db)
    by_source, by_name = build_view_indexes(views, config['REVIEW_VIEW_SUFFIX'])
    legacy_records = load_legacy_records(args.input)

    planned = []
    errors = []
    for legacy_record in legacy_records:
        try:
            planned.append(migrate_record(
                vuln_db,
                legacy_record,
                by_source,
                by_name,
                config['REVIEW_VIEW_SUFFIX'],
            ))
        except Exception as exc:
            email = (legacy_record.get('email') or '<missing email>').strip()
            errors.append((email, str(exc)))

    if not args.dry_run and planned and not args.yes:
        answer = input(f'Migrate {len(planned)} subscription(s)? [y/N] ').strip().casefold()
        if answer not in {'y', 'yes'}:
            print('Cancelled.')
            return 1

    inserted = updated = skipped = 0
    warning_count = 0
    now = datetime.now(timezone.utc)

    for record in planned:
        email = record['email']
        warnings = record['warnings']
        if warnings:
            warning_count += 1
            print(f'WARN {email}: skipped unmappable collections: {", ".join(warnings)}')

        existing = collection.find_one({'email': email})
        if existing and is_already_migrated(existing) and not args.force:
            skipped += 1
            print(f'SKIP {email}: already migrated')
            continue

        update_fields = {
            'newsletter_profile': record['newsletter_profile'],
            'report_profile': record['report_profile'],
            'updated_at': now,
        }
        if existing is None:
            document = {
                'email': email,
                'team': record['team'],
                **update_fields,
                'created_at': now,
            }
            if record.get('_id') is not None:
                document['_id'] = record['_id']
            action = 'INSERT'
            if args.dry_run:
                inserted += 1
            else:
                collection.insert_one(document)
                inserted += 1
        else:
            if (existing.get('team') or '').strip() != record['team']:
                update_fields['team'] = record['team']
            action = 'UPDATE'
            if args.dry_run:
                updated += 1
            else:
                collection.update_one({'email': email}, {'$set': update_fields})
                updated += 1

        newsletter_enabled = record['newsletter_profile']['enabled']
        collections = record['newsletter_profile']['filters']['collections']
        print(
            f'{action} {email}: newsletter={"enabled" if newsletter_enabled else "disabled"}, '
            f'{len(collections)} collection(s), report=disabled',
        )

    print(
        f'Done. inserted={inserted}, updated={updated}, skipped={skipped}, '
        f'warnings={warning_count}, errors={len(errors)}'
        + (' (dry run)' if args.dry_run else ''),
    )
    for email, message in errors:
        print(f'ERROR {email}: {message}', file=sys.stderr)
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())

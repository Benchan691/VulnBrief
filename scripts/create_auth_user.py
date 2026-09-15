#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from auth.store import ensure_account_hub_user, upsert_user
from core.bootstrap import BASE_DIR, configure_application


def main():
    parser = argparse.ArgumentParser(
        description='Create a local login user or approve an Account Hub user in local MongoDB.',
    )
    parser.add_argument('username', help='Login username')
    parser.add_argument(
        'password',
        nargs='?',
        help='Local login password (required when Account Hub is disabled)',
    )
    parser.add_argument('--email', help='Optional contact email address (not a login identifier)')
    args = parser.parse_args()
    config = configure_application(BASE_DIR)
    if config.get('ACCOUNT_HUB_ENABLED'):
        ensure_account_hub_user(args.username, args.email)
        print(f'Account Hub user {args.username!r} approved in web.auth.')
        return
    if not args.password:
        parser.error('password is required when Account Hub is disabled')
    upsert_user(args.username, args.password, email=args.email)
    print(f'Local user {args.username!r} saved to web.auth.')


if __name__ == '__main__':
    main()

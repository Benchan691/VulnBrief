#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from auth_store import upsert_user
from bootstrap import BASE_DIR, configure_application


def main():
    parser = argparse.ArgumentParser(description='Create or reset a web login user in local MongoDB.')
    parser.add_argument('username', help='Login username')
    parser.add_argument('password', help='Login password')
    parser.add_argument('--email', help='Optional email address that can also be used to sign in')
    args = parser.parse_args()
    configure_application(BASE_DIR)
    upsert_user(args.username, args.password, email=args.email)
    print(f'User {args.username!r} saved to web.auth.')


if __name__ == '__main__':
    main()

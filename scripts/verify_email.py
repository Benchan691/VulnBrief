#!/usr/bin/env python3
"""One-time SMTP smoke test. Not wired into the web UI."""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.bootstrap import BASE_DIR, configure_application
from integrations.email import Mailer


def main():
    parser = argparse.ArgumentParser(
        description='Send a one-time SMTP verification email (test only).',
    )
    parser.add_argument('email', help='Recipient email address')
    args = parser.parse_args()
    config = configure_application(BASE_DIR)
    try:
        with Mailer(config) as mailer:
            mailer.send_email(args.email, {
                'subject': 'Security Portal email verification',
                'html': '<p>This is a test email from Security Portal.</p>',
            })
    except Exception as exc:
        print(f'Failed to send verification email to {args.email!r}: {exc}', file=sys.stderr)
        return 1
    print(f'Verification email sent to {args.email!r}.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

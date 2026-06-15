#!/usr/bin/env python3
"""One-time utility to delete Company AI SmartBot chats for the configured account."""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bootstrap import BASE_DIR, configure_worker
from report_harness import CompanyAIProvider, ProviderError


CHAT_ID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)
CHAT_ID_KEYS = ('conversationId', 'conversation_id', 'uid', 'chatId', 'chat_id', 'id')
LIST_PATH_CANDIDATES = ('common/getSkillAllChatList',)


def _is_chat_id(value):
    return isinstance(value, str) and bool(CHAT_ID_RE.match(value.strip()))


def extract_chat_ids(payload):
    ids = []

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in CHAT_ID_KEYS and _is_chat_id(item):
                    ids.append(item.strip())
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(payload)
    unique = []
    seen = set()
    for chat_id in ids:
        key = chat_id.casefold()
        if key not in seen:
            seen.add(key)
            unique.append(chat_id)
    return unique


def _list_page_total(payload):
    if not isinstance(payload, dict):
        return None
    data = payload.get('data')
    if isinstance(data, dict):
        for key in ('total', 'totalCount', 'totalNum', 'count'):
            total = data.get(key)
            if isinstance(total, int):
                return total
    for key in ('total', 'totalCount', 'totalNum', 'count'):
        total = payload.get(key)
        if isinstance(total, int):
            return total
    return None


def _load_ids_file(path):
    ids = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        value = line.strip()
        if not value or value.startswith('#'):
            continue
        if not _is_chat_id(value):
            raise ValueError(f'Invalid chat id in {path}: {value!r}')
        ids.append(value)
    return ids


def fetch_all_chat_ids(provider, *, page_size=50, list_path=None):
    configured_path = list_path or None
    paths = [configured_path] if configured_path else list(LIST_PATH_CANDIDATES)
    last_error = None

    for candidate in paths:
        collected = []
        page = 1
        total = None
        try:
            while True:
                payload = provider.list_chats_page(
                    page=page,
                    page_size=page_size,
                    list_path=candidate,
                )
                if payload.get('success') is False:
                    raise ProviderError(payload.get('msg') or f'Chat list failed for {candidate}.')
                page_ids = extract_chat_ids(payload)
                if total is None:
                    total = _list_page_total(payload)
                if not page_ids:
                    break
                collected.extend(page_ids)
                if total is not None and len(collected) >= total:
                    break
                if len(page_ids) < page_size:
                    break
                page += 1
            if collected or payload.get('success') is True:
                return collected, candidate
        except Exception as exc:
            last_error = exc
            continue

    raise ProviderError(
        'Unable to list Company AI chats. Set COMPANY_AI_CHAT_LIST_PATH in .env '
        'to the correct SmartBot list endpoint, or pass --ids / --ids-file. '
        f'Last error: {last_error}',
    )


def main():
    parser = argparse.ArgumentParser(
        description='Delete all Company AI SmartBot chats for the configured account.',
    )
    parser.add_argument(
        '--ids',
        nargs='*',
        metavar='CHAT_ID',
        help='Explicit conversation UUIDs to delete (skips list API).',
    )
    parser.add_argument(
        '--ids-file',
        help='Text file with one conversation UUID per line.',
    )
    parser.add_argument(
        '--list-path',
        help='Override COMPANY_AI_CHAT_LIST_PATH for this run.',
    )
    parser.add_argument(
        '--page-size',
        type=int,
        default=50,
        help='Page size when listing chats (default: 50).',
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Print chat ids that would be deleted without calling deleteChat.',
    )
    parser.add_argument(
        '--yes',
        action='store_true',
        help='Delete without interactive confirmation.',
    )
    args = parser.parse_args()

    config = configure_worker(BASE_DIR)
    provider = CompanyAIProvider(config)
    provider.ensure_session()

    if args.ids or args.ids_file:
        chat_ids = list(args.ids or [])
        if args.ids_file:
            chat_ids.extend(_load_ids_file(args.ids_file))
        list_source = 'manual'
    else:
        chat_ids, list_source = fetch_all_chat_ids(
            provider,
            page_size=max(args.page_size, 1),
            list_path=args.list_path,
        )

    unique_ids = []
    seen = set()
    for chat_id in chat_ids:
        key = chat_id.casefold()
        if key not in seen:
            seen.add(key)
            unique_ids.append(chat_id)

    if not unique_ids:
        print('No Company AI chats found.')
        return 0

    print(f'Found {len(unique_ids)} chat(s) via {list_source}.')
    for chat_id in unique_ids:
        print(f'  {chat_id}')

    if args.dry_run:
        print('Dry run only; no chats deleted.')
        return 0

    if not args.yes:
        answer = input(f'Delete {len(unique_ids)} chat(s)? [y/N] ').strip().casefold()
        if answer not in {'y', 'yes'}:
            print('Cancelled.')
            return 1

    deleted = 0
    failed = 0
    for chat_id in unique_ids:
        try:
            provider.delete_chat(chat_id)
            deleted += 1
            print(f'Deleted {chat_id}')
        except Exception as exc:
            failed += 1
            print(f'Failed {chat_id}: {exc}', file=sys.stderr)

    print(f'Done. Deleted {deleted}, failed {failed}.')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())

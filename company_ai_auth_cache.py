import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthEntry:
    system_token: str
    bot_token: str
    expires_at: float


def _cache_key(base_url, username):
    return (base_url.rstrip('/'), username)


_lock = threading.Lock()
_tokens = {}
_failures = {}
_blocked = set()


def get_tokens(base_url, username):
    key = _cache_key(base_url, username)
    with _lock:
        entry = _tokens.get(key)
        if entry is None or entry.expires_at <= time.monotonic():
            return None
        return entry


def set_tokens(base_url, username, system_token, bot_token, ttl_seconds):
    key = _cache_key(base_url, username)
    with _lock:
        _tokens[key] = AuthEntry(
            system_token=system_token,
            bot_token=bot_token,
            expires_at=time.monotonic() + max(int(ttl_seconds), 1),
        )


def invalidate(base_url, username):
    key = _cache_key(base_url, username)
    with _lock:
        _tokens.pop(key, None)


def is_login_blocked(base_url, username):
    key = _cache_key(base_url, username)
    with _lock:
        return key in _blocked


def set_login_blocked(base_url, username):
    key = _cache_key(base_url, username)
    with _lock:
        _blocked.add(key)


def record_login_failure(base_url, username):
    key = _cache_key(base_url, username)
    with _lock:
        count = _failures.get(key, 0) + 1
        _failures[key] = count
        return count


def reset_login_failures(base_url, username):
    key = _cache_key(base_url, username)
    with _lock:
        _failures.pop(key, None)


def clear_auth_state_for_tests():
    with _lock:
        _tokens.clear()
        _failures.clear()
        _blocked.clear()

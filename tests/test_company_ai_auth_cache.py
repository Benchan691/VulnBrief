import time

import pytest

import company_ai_auth_cache as cache


@pytest.fixture(autouse=True)
def reset_auth_cache():
    cache.clear_auth_state_for_tests()
    yield
    cache.clear_auth_state_for_tests()


def test_set_and_get_tokens_before_expiry(monkeypatch):
    times = [100.0]
    monkeypatch.setattr(cache.time, 'monotonic', lambda: times[0])
    cache.set_tokens('https://company.example', 'owner', 'Bearer system', 'Bearer bot', 60)
    entry = cache.get_tokens('https://company.example', 'owner')
    assert entry.system_token == 'Bearer system'
    assert entry.bot_token == 'Bearer bot'
    times[0] = 150.0
    assert cache.get_tokens('https://company.example', 'owner') is not None
    times[0] = 161.0
    assert cache.get_tokens('https://company.example', 'owner') is None


def test_invalidate_removes_tokens():
    cache.set_tokens('https://company.example', 'owner', 'Bearer system', 'Bearer bot', 60)
    cache.invalidate('https://company.example', 'owner')
    assert cache.get_tokens('https://company.example', 'owner') is None


def test_login_failure_counter_and_block():
    assert cache.record_login_failure('https://company.example', 'owner') == 1
    assert cache.record_login_failure('https://company.example', 'owner') == 2
    assert not cache.is_login_blocked('https://company.example', 'owner')
    cache.set_login_blocked('https://company.example', 'owner')
    assert cache.is_login_blocked('https://company.example', 'owner')


def test_reset_login_failures_clears_counter():
    cache.record_login_failure('https://company.example', 'owner')
    cache.record_login_failure('https://company.example', 'owner')
    cache.reset_login_failures('https://company.example', 'owner')
    assert cache.record_login_failure('https://company.example', 'owner') == 1

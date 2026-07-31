from app import app
from core.i18n import catalog, html_lang, normalize_locale, t


def test_normalize_locale_aliases():
    assert normalize_locale('ch') == 'ch'
    assert normalize_locale('zh-CN') == 'ch'
    assert normalize_locale('zh-Hans') == 'ch'
    assert normalize_locale('en') == 'en'
    assert normalize_locale('nope') == 'en'
    assert normalize_locale(None) == 'en'


def test_t_defaults_to_english_key():
    assert t('Subscriptions', locale='en') == 'Subscriptions'
    assert t('Subscriptions', locale='ch') == '订阅管理'
    assert t('Security Portal', locale='ch') == '安全门户'


def test_t_formats_placeholders():
    assert t('{count} selected', locale='ch', count=3) == '已选 3 项'
    assert t('{count} selected', locale='en', count=3) == '3 selected'


def test_html_lang_and_catalog():
    assert html_lang('en') == 'en'
    assert html_lang('ch') == 'zh-Hans'
    assert 'Subscriptions' in catalog('ch')
    assert catalog('en') == {}


def test_locale_route_sets_cookie_and_redirects():
    client = app.test_client()
    response = client.get('/locale/ch?next=/login', follow_redirects=False)
    assert response.status_code == 302
    assert response.headers['Location'].endswith('/login')
    assert 'lang=ch' in response.headers.get('Set-Cookie', '')


def test_login_renders_simplified_chinese_with_cookie():
    client = app.test_client()
    client.set_cookie('lang', 'ch')
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode('utf-8')
    assert 'lang="zh-Hans"' in html
    assert '登录' in html
    assert '通讯管理' in html


def test_login_error_translates_with_cookie():
    client = app.test_client()
    client.set_cookie('lang', 'ch')
    response = client.post('/login', data={'username': 'x', 'password': 'y'})
    assert response.status_code == 200
    assert '用户名或密码无效' in response.data.decode('utf-8')

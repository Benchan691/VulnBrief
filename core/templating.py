from markupsafe import Markup, escape

from core.i18n import catalog, get_locale, html_lang, t


def nl2br(value):
    if value is None:
        return ''
    text = escape(str(value))
    normalized = text.replace('\r\n', '\n').replace('\r', '\n')
    return Markup(normalized.replace('\n', Markup('<br>\n')))


def register_template_filters(application):
    application.add_template_filter(nl2br, 'nl2br')
    application.jinja_env.globals['t'] = t

    @application.context_processor
    def inject_i18n():
        from core.auth import current_user

        locale = get_locale()
        try:
            user = current_user()
        except RuntimeError:
            user = None
        return {
            'locale': locale,
            'html_lang': html_lang(locale),
            'i18n_catalog': catalog(locale),
            'current_user': {
                'username': user.get('username') or '',
                'email': user.get('email') or '',
                'role': user.get('role') or 'user',
                'must_change_password': bool(user.get('must_change_password')),
                'disabled': bool(user.get('disabled')),
            } if user else None,
            'is_admin': bool(user and user.get('role') in {'admin', 'sub_admin'}),
            'is_top_admin': bool(user and user.get('role') == 'admin'),
        }

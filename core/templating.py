from markupsafe import Markup, escape


def nl2br(value):
    if value is None:
        return ''
    text = escape(str(value))
    normalized = text.replace('\r\n', '\n').replace('\r', '\n')
    return Markup(normalized.replace('\n', Markup('<br>\n')))


def register_template_filters(application):
    application.add_template_filter(nl2br, 'nl2br')

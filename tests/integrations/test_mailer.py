from unittest.mock import MagicMock, patch

from integrations.email import Mailer, prepare_html_for_email


def test_prepare_html_for_email_inlines_styles():
    html = (
        '<html><head><style>'
        '.item-table th { background: #f4f0ff; }'
        '</style></head><body>'
        '<table class="item-table"><tr><th>Title</th></tr></table>'
        '</body></html>'
    )
    prepared = prepare_html_for_email(html)
    assert 'style=' in prepared
    assert 'background' in prepared
    assert 'Title' in prepared


def test_prepare_html_for_email_inlines_enriched_card_tables():
    html = (
        '<html><head><style>'
        '.vulnerability-card td { border-left: 4px solid #0f766e; background: #f7faf9; }'
        '</style></head><body>'
        '<table class="vulnerability-card"><tr><td>Card body</td></tr></table>'
        '</body></html>'
    )
    prepared = prepare_html_for_email(html)
    assert 'border-left' in prepared
    assert 'background' in prepared
    assert 'Card body' in prepared


def test_mailer_connect_send_email_and_close():
    config = {
        'SMTP_HOST': 'smtp.example.com',
        'SMTP_PORT': 587,
        'SMTP_FROM': 'noreply@example.com',
        'SMTP_USERNAME': 'user',
        'SMTP_PASSWORD': 'secret',
        'SMTP_USE_TLS': True,
        'SMTP_USE_SSL': False,
    }
    smtp = MagicMock()
    with patch('integrations.email.smtplib.SMTP', return_value=smtp) as smtp_cls:
        mailer = Mailer(config)
        mailer.connect()
        smtp_cls.assert_called_once_with('smtp.example.com', 587, timeout=30)
        smtp.starttls.assert_called_once_with()
        smtp.login.assert_called_once_with('user', 'secret')

        mailer.send_email('to@example.com', {
            'subject': 'Hello',
            'html': '<p>Body</p>',
        })
        smtp.send_message.assert_called_once()
        message = smtp.send_message.call_args.args[0]
        assert message['To'] == 'to@example.com'
        assert message['Subject'] == 'Hello'
        assert message['From'] == 'noreply@example.com'

        mailer.close()
        smtp.quit.assert_called_once_with()


def test_mailer_context_manager_connects_and_closes():
    config = {
        'SMTP_HOST': 'smtp.example.com',
        'SMTP_FROM': 'noreply@example.com',
        'SMTP_USE_TLS': False,
        'SMTP_USE_SSL': False,
    }
    smtp = MagicMock()
    with patch('integrations.email.smtplib.SMTP', return_value=smtp):
        with Mailer(config) as mailer:
            mailer.send_email('to@example.com', {
                'subject': 'Hello',
                'html': '<p>Body</p>',
                'text': 'Body',
            })
        smtp.send_message.assert_called_once()
        smtp.quit.assert_called_once_with()


def test_mailer_send_email_requires_connect():
    mailer = Mailer({'SMTP_HOST': 'smtp.example.com', 'SMTP_FROM': 'a@b.c'})
    try:
        mailer.send_email('to@example.com', {'subject': 'Hi', 'html': '<p>x</p>'})
        assert False, 'expected RuntimeError'
    except RuntimeError as exc:
        assert 'not connected' in str(exc)


def test_mailer_requires_smtp_host_and_sender():
    try:
        Mailer({}).connect()
        assert False, 'expected ValueError'
    except ValueError as exc:
        assert 'SMTP_HOST' in str(exc)

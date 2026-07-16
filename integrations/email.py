import smtplib
from email.message import EmailMessage

from premailer import transform


DEFAULT_TEXT_BODY = 'Open this email in an HTML-capable mail client.'


def prepare_html_for_email(html):
    return transform(
        html,
        keep_style_tags=False,
        remove_classes=False,
        strip_important=False,
    )


class Mailer:
    def __init__(self, config):
        self.config = config
        self._smtp = None
        self._sender = None

    def connect(self):
        if self._smtp is not None:
            return self
        host = self.config.get('SMTP_HOST')
        sender = self.config.get('SMTP_FROM') or self.config.get('SMTP_USERNAME')
        if not host or not sender:
            raise ValueError('SMTP_HOST and SMTP_FROM or SMTP_USERNAME are required for email.')
        port = int(self.config.get('SMTP_PORT') or 587)
        smtp_class = smtplib.SMTP_SSL if self.config.get('SMTP_USE_SSL') else smtplib.SMTP
        smtp = smtp_class(host, port, timeout=30)
        try:
            if self.config.get('SMTP_USE_TLS') and not self.config.get('SMTP_USE_SSL'):
                smtp.starttls()
            username = self.config.get('SMTP_USERNAME')
            password = self.config.get('SMTP_PASSWORD')
            if username and password:
                smtp.login(username, password)
        except Exception:
            smtp.close()
            raise
        self._smtp = smtp
        self._sender = sender
        return self

    def send_email(self, receiver, email):
        if self._smtp is None:
            raise RuntimeError('Mailer is not connected. Call connect() first.')
        if not isinstance(email, dict):
            raise ValueError('email must be a dict with subject and html.')
        subject = email.get('subject')
        html = email.get('html')
        if not subject or html is None:
            raise ValueError('email requires subject and html.')
        message = EmailMessage()
        message['From'] = self._sender
        message['To'] = receiver
        message['Subject'] = subject
        message.set_content(email.get('text') or DEFAULT_TEXT_BODY)
        message.add_alternative(prepare_html_for_email(html), subtype='html')
        self._smtp.send_message(message)

    def close(self):
        smtp = self._smtp
        self._smtp = None
        self._sender = None
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

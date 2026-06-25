import smtplib
from email.message import EmailMessage


def send_html_email(config, to_address, subject, html):
    host = config.get('SMTP_HOST')
    sender = config.get('SMTP_FROM') or config.get('SMTP_USERNAME')
    if not host or not sender:
        raise ValueError('SMTP_HOST and SMTP_FROM or SMTP_USERNAME are required for email.')
    message = EmailMessage()
    message['From'] = sender
    message['To'] = to_address
    message['Subject'] = subject
    message.set_content('Open this email in an HTML-capable mail client.')
    message.add_alternative(html, subtype='html')
    port = int(config.get('SMTP_PORT') or 587)
    smtp_class = smtplib.SMTP_SSL if config.get('SMTP_USE_SSL') else smtplib.SMTP
    with smtp_class(host, port, timeout=30) as smtp:
        if config.get('SMTP_USE_TLS') and not config.get('SMTP_USE_SSL'):
            smtp.starttls()
        username = config.get('SMTP_USERNAME')
        password = config.get('SMTP_PASSWORD')
        if username and password:
            smtp.login(username, password)
        smtp.send_message(message)

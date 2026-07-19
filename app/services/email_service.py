"""
Email service: sends the high-risk notification email.

TODO (FYP2 implementation):
    Fill in the SMTP settings in .env. Until then this logs to the console.
"""
import smtplib
from email.mime.text import MIMEText

from config.settings import settings


def send_alert_email(to: str, subject: str, body: str) -> bool:
    if not settings.SMTP_HOST:
        print(f"[email] (disabled) would send to {to}: {subject}")
        return False
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_USER
    msg["To"] = to
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            if settings.SMTP_USER:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as exc:
        print(f"[email] send failed: {exc}")
        return False

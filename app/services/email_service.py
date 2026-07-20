"""
Email service: sends the high-risk notification email.

The message is HTML and carries a direct "Open in CyREN" link to the incident
so an analyst can jump straight into the system. If SMTP is not configured in
.env, the full message (including the link) is logged instead of sent, so the
behaviour is still visible during a demo.
"""
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config.settings import settings

log = logging.getLogger(__name__)


def _plain_from_html(html: str) -> str:
    import re
    text = re.sub(r"<[^>]+>", "", html)
    return re.sub(r"\n\s*\n\s*\n+", "\n\n", text).strip()


def send_alert_email(to: str, subject: str, html_body: str) -> bool:
    """Send (or, if SMTP is unset, log) an HTML alert email. Returns True only
    when a message was actually handed to an SMTP server."""
    if not settings.SMTP_HOST:
        log.warning("[email] SMTP not configured (set SMTP_HOST in .env); "
                    "would have sent to %s:\n  Subject: %s\n%s",
                    to or "(no ALERT_EMAIL_TO)", subject, _plain_from_html(html_body))
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_USER or "cyren@localhost"
    msg["To"] = to
    msg.attach(MIMEText(_plain_from_html(html_body), "plain"))
    msg.attach(MIMEText(html_body, "html"))
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
            server.starttls()
            if settings.SMTP_USER:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)
        log.info("[email] alert sent to %s", to)
        return True
    except Exception as exc:
        log.error("[email] send failed: %s", exc)
        return False


def build_alert_email(state: dict) -> tuple:
    """Build (subject, html_body) for a high-risk incident, including a direct
    link into CyREN."""
    ip = state.get("source_ip", "unknown")
    attack = state.get("attack_type", "attack")
    conf = state.get("confidence")
    try:
        conf_pct = f"{float(conf) * 100:.0f}%"
    except (TypeError, ValueError):
        conf_pct = "n/a"
    summary = state.get("llm_summary") or {}
    # deep-link: the app reads #ip=<ip> on load and jumps to that source
    link = settings.APP_BASE_URL.rstrip("/") + "/#ip=" + ip

    subject = f"[CyREN] High risk: {attack} from {ip} - IP blocked"
    html = f"""\
<div style="font-family:Arial,Helvetica,sans-serif;max-width:620px;margin:auto;
            border:2px solid #1a1a1a;border-radius:10px;overflow:hidden">
  <div style="background:#0d2c50;color:#ffd60a;padding:16px 20px">
    <div style="font-size:20px;font-weight:800;letter-spacing:.5px">CyREN</div>
    <div style="color:#fff;font-size:12px">SOC INCIDENT RESPONSE</div>
  </div>
  <div style="background:#ff5252;color:#fff;padding:10px 20px;font-weight:700">
    HIGH RISK — automatic block applied
  </div>
  <div style="padding:20px;color:#1a1a1a;font-size:14px;line-height:1.6">
    <p><b>{attack}</b> was detected from <code>{ip}</code> and the source IP has
       been blocked at the firewall.</p>
    <table style="border-collapse:collapse;width:100%;margin:10px 0">
      <tr><td style="padding:4px 8px;color:#666">Source IP</td>
          <td style="padding:4px 8px"><code>{ip}</code></td></tr>
      <tr><td style="padding:4px 8px;color:#666">Attack type</td>
          <td style="padding:4px 8px">{attack}</td></tr>
      <tr><td style="padding:4px 8px;color:#666">Confidence</td>
          <td style="padding:4px 8px">{conf_pct}</td></tr>
      <tr><td style="padding:4px 8px;color:#666">Action taken</td>
          <td style="padding:4px 8px">iptables DROP rule added</td></tr>
    </table>
    <p style="margin:8px 0"><b>What happened:</b><br>{summary.get('what_happened', 'N/A')}</p>
    <p style="margin:8px 0"><b>Recommended action:</b><br>{summary.get('what_should_be_done', 'N/A')}</p>
    <p style="text-align:center;margin:24px 0 8px">
      <a href="{link}" style="background:#0d2c50;color:#ffd60a;text-decoration:none;
         font-weight:800;padding:12px 24px;border-radius:8px;display:inline-block">
        Open this incident in CyREN &rarr;</a>
    </p>
    <p style="text-align:center;font-size:12px;color:#888">{link}</p>
  </div>
</div>"""
    return subject, html

"""
notifier.py — Email notification when a scan finishes, via plain SMTP so it
works with Gmail (app password), Outlook, or any SMTP relay without pulling
in a third-party email service SDK.
"""

import re
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class NotifierError(Exception):
    """Human-readable message about why the notification email couldn't be sent."""
    pass


def _severity_counts(findings: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        if sev in counts:
            counts[sev] += 1
    return counts


def build_summary_email(project_name: str, risk_score: float, security_findings: list[dict],
                         dependency_findings: list[dict]) -> tuple[str, str]:
    """Returns (subject, plain-text body)."""
    sec_counts = _severity_counts(security_findings)
    dep_counts = _severity_counts(dependency_findings)

    subject = f"CodeSage AI scan complete: {project_name} (risk {risk_score:.0f}/100)"
    body = (
        f"Scan finished for {project_name}.\n\n"
        f"Risk score: {risk_score:.0f}/100\n\n"
        f"Security findings: {sum(sec_counts.values())} total\n"
        f"  Critical: {sec_counts['critical']}  High: {sec_counts['high']}  "
        f"Medium: {sec_counts['medium']}  Low: {sec_counts['low']}\n\n"
        f"Dependency vulnerabilities: {sum(dep_counts.values())} total\n"
        f"  Critical: {dep_counts['critical']}  High: {dep_counts['high']}  "
        f"Medium: {dep_counts['medium']}  Low: {dep_counts['low']}\n\n"
        f"Open CodeSage AI to see the full report, AI review, and PDF/SARIF export.\n"
    )
    return subject, body


def send_scan_complete_email(
    smtp_host: str, smtp_port: int, smtp_user: str, smtp_password: str,
    to_addr: str, project_name: str, risk_score: float,
    security_findings: list[dict], dependency_findings: list[dict],
    use_tls: bool = True,
) -> None:
    to_addrs = [a.strip() for a in re.split(r"[,;]", to_addr or "") if a.strip()]
    if not to_addrs:
        raise NotifierError("No recipient email address provided.")
    if not smtp_host or not smtp_user or not smtp_password:
        raise NotifierError("SMTP host, username, and password must all be set to send email notifications.")

    subject, body = build_summary_email(project_name, risk_score, security_findings, dependency_findings)

    msg = MIMEMultipart()
    msg["From"] = smtp_user
    msg["To"] = ", ".join(to_addrs)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        if use_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
                server.starttls(context=context)
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, to_addrs, msg.as_string())
        else:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=20) as server:
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, to_addrs, msg.as_string())
    except smtplib.SMTPAuthenticationError:
        raise NotifierError("SMTP authentication failed — check the username/password (Gmail needs an App Password, not your regular password).")
    except smtplib.SMTPConnectError:
        raise NotifierError(f"Couldn't connect to {smtp_host}:{smtp_port}. Check the host/port.")
    except (smtplib.SMTPException, OSError) as e:
        raise NotifierError(f"Failed to send notification email: {e}")

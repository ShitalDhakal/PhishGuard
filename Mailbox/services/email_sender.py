from email import encoders
from email.mime.base import MIMEBase
import json
import smtplib
import os
from django.http import JsonResponse
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from Mailbox.models import MailBox
from django.utils import timezone

load_dotenv()

SENDER_EMAIL   = os.getenv("IMAP_SENDER_EMAIL")
SENDER_APP_PASSWORD = os.getenv("IMAP_SENDER_PASSWORD")
RECIPIENT_EMAIL = os.getenv("RECIPIENT_EMAIL")   # destination account

# --- Phishing-like email content ---
# Spoofed "From" header: display name + fake email (Gmail may replace with your real address)
spoofed_from = "Google Security <security@amazon.com>"   # this is what the recipient sees
subject = "Action Required: Your Amazon account has been limited"
reply_to = "no-reply@amazon.com"   # optional spoofed reply-to

# Plain text fallback
text_body = """
Dear user,

We noticed unusual activity on your Amazon account.
Please verify your identity within 24 hours to avoid suspension.

Click here to verify: http://192.168.1.100/phishing-demo (test link)
"""

# HTML body with a deceptive link
html_body = """
<html>
  <body>
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd;">
      <img src="2020logs.duckdns.org" alt="amazon" width="100">
      <h2 style="color:#c00;">Your account has been limited</h2>
      <p>Dear Customer,</p>
      <p>We have detected unusual activity on your Amazon account. To prevent further access, we have temporarily limited your account.</p>
      <p>Please <a href="http://192.168.1.100/phishing-demo" style="color:#0070ba; font-weight:bold;">click here to restore your account</a>.</p>
      <p>This must be completed within 24 hours.</p>
      <p>Sincerely,<br>Amazon Security Team</p>
    </div>
  </body>
</html>
"""

# --- Build the email ---
msg = MIMEMultipart("alternative")
msg["From"] = spoofed_from
msg["To"] = RECIPIENT_EMAIL
msg["Subject"] = subject


def sendEmail_Api(request):
    try:
        data = {}
        if request.body:
            data = json.loads(request.body)
        address = data.get("address")
        subject = data.get("subject")
        body = data.get("body")
        send_file = data.get("send_file", False)
        file_path = None
        if(send_file):
            current_dir = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(current_dir, "eicar.txt")

        sendEmail(address, subject, body, file_path)
        return JsonResponse({"message": f"Email sent to {address}", "status": 200}, safe=False)
    except Exception as e:
        print(f"Error in sendEmail_Api: {e}")
        return JsonResponse({"message": "Server error", "status": 500}, safe=False)

def sendEmail(address, subject, body, file_path=None):
    
    mailbox = MailBox.objects.first()
    try:
        with smtplib.SMTP_SSL(mailbox.imap_server, 465) as server:
            server.login(mailbox.address, mailbox.app_password)
            msg = MIMEMultipart()
            msg['From'] = mailbox.address
            msg['To'] = address
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            if file_path and os.path.exists(file_path):
                with open(file_path, "rb") as attachment:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attachment.read())

                encoders.encode_base64(part)
                filename = os.path.basename(file_path)
                part.add_header(
                    "Content-Disposition", f"attachment; filename= {filename}"
                )
                msg.attach(part)
            elif file_path:
                print(
                    f"Warning: Specified file not found at {file_path}. Sending email without attachment."
                )
            server.send_message(msg)
        print(f"Email sent to {address}")
    except Exception as e:
        print(f"Failed to send email: {e}")


def send_phishing_alert(report):
    """
    Sends an alert email to the original recipient of a confirmed
    phishing or suspicious email.

    Called automatically by analyze_email.py after risk scoring.

    Args:
        report: AnalysisReport instance
    """
    email_record = report.email_id
    to_address   = email_record.recipient

    if not to_address:
        print("[Alert] No recipient address found — skipping alert.")
        return

    # Choose subject and message based on verdict
    if report.verdict == "Malicious":
        subject = "PhishGuard Alert: Phishing Email Detected in Your Inbox"
        urgency = "confirmed as PHISHING"
        action  = "Delete it from your inbox IMMEDIATELY. Do NOT click any links or open attachments."
        color   = "#c0392b"
    else:  # Suspicious
        subject = "⚠️ PhishGuard Alert: Suspicious Email Detected"
        urgency = "flagged as SUSPICIOUS"
        action  = "Proceed with caution. Do not click any links or open attachments until our analyst reviews it."
        color   = "#e67e22"

    body = f"""
<html>
  <body style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px;">
    <div style="background:{color}; color:white; padding:15px; border-radius:6px;">
      <h2 style="margin:0;">PhishGuard Security Alert</h2>
    </div>
    <div style="padding:20px; border:1px solid #ddd; margin-top:10px; border-radius:6px;">
      <p>Hello,</p>
      <p>An email in your inbox has been <strong>{urgency}</strong> by PhishGuard.</p>
      <table style="width:100%; background:#f9f9f9; padding:10px; border-radius:4px; border-collapse:collapse;">
        <tr style="border-bottom:1px solid #eee;">
          <td style="padding:6px;"><strong>Original Subject:</strong></td>
          <td style="padding:6px;">{email_record.subject}</td>
        </tr>
        <tr style="border-bottom:1px solid #eee;">
          <td style="padding:6px;"><strong>Original From:</strong></td>
          <td style="padding:6px;">{email_record.sender}</td>
        </tr>
        <tr style="border-bottom:1px solid #eee;">
          <td style="padding:6px;"><strong>Risk Score:</strong></td>
          <td style="padding:6px;">{report.overall_risk_score}/100</td>
        </tr>
        <tr>
          <td style="padding:6px;"><strong>Verdict:</strong></td>
          <td style="padding:6px; color:{color};"><strong>{report.verdict}</strong></td>
        </tr>
      </table>
      <p style="margin-top:20px;"><strong>Action Required:</strong></p>
      <p style="color:{color}; font-size:15px;"><strong>{action}</strong></p>
      <p>If you believe this is a false positive, please contact your IT security team.</p>
      <hr style="margin-top:30px; border:none; border-top:1px solid #eee;">
      <p style="font-size:12px; color:#888;">
        This is an automated alert from PhishGuard Email Security System.<br>
        Do not reply to this email.
      </p>
    </div>
  </body>
</html>
"""

    mailbox = MailBox.objects.first()
    if not mailbox:
        print("[Alert] No mailbox configured — cannot send alert.")
        return

    try:
        with smtplib.SMTP_SSL(mailbox.imap_server, 465) as server:
            server.login(mailbox.address, mailbox.app_password)
            msg = MIMEMultipart("alternative")
            msg["From"]    = mailbox.address
            msg["To"]      = to_address
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "html"))
            server.send_message(msg)

        report.alert_sent    = True
        report.alert_sent_at = report.created_at if report.created_at else timezone.now()
        report.save(update_fields=["alert_sent", "alert_sent_at"])
        print(f"[Alert] Sent to {to_address} — report ID {report.id}")

    except Exception as e:
        print(f"[Alert] Failed to send: {e}")
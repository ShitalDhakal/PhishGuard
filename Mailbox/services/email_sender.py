import smtplib
import os
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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
msg["Reply-To"] = reply_to

# Attach plain text and HTML parts
msg.attach(MIMEText(text_body, "plain"))
msg.attach(MIMEText(html_body, "html"))

# --- Send via Gmail SMTP ---
try:
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
    print(f"Demo phishing email sent to {RECIPIENT_EMAIL}")
except Exception as e:
    print(f"Failed to send: {e}")
import smtplib
import os
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

load_dotenv()

sender   = os.getenv("IMAP_EMAIL")
password = os.getenv("IMAP_PASSWORD")
receiver = "yuri.if2061@gmail.com"   # destination account

# BUILD
msg = MIMEMultipart("alternative")
msg["From"]    = sender
msg["To"]      = receiver
msg["Subject"] = "PhishGuard Demo — HTML Email"

# PART 1 — plain text fallback
text = "Your account has been suspended. Click here to restore."
msg.attach(MIMEText(text, "plain"))

# PART 2 — HTML
html = """
<html>
  <body>
    <h2 style="color:red;">⚠️ Account Suspended</h2>
    <p>Dear Customer,</p>
    <p>Your account has been suspended due to suspicious activity.</p>
    <a href="http://paypa1-secure-login.ru/restore?token=abc123"
       style="background:blue; color:white; padding:10px;">
       Restore Account
    </a>
    <p>Failure to act within <b>24 hours</b> will result in permanent suspension.</p>
    <p>— PayPal Security Team</p>
  </body>
</html>
"""
msg.attach(MIMEText(html, "html"))

# SEND
with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
    smtp.login(sender, password)
    smtp.sendmail(sender, receiver, msg.as_string())
    print("Email sent successfully.")
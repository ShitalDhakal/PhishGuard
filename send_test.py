import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText

# --- Mailtrap SMTP credentials ---
SMTP_HOST = "sandbox.smtp.mailtrap.io"
SMTP_PORT = 2525
USERNAME  = "cb966a82d7350f"
PASSWORD  = "a5bf1327fa6082"

# --- Build the spoofed phishing email ---
msg = MIMEMultipart("alternative")
msg["From"]    = "security-update@paypal-verify.com"  # Spoofed sender display/address
msg["To"]      = "employee@yourorganization.com"     # The target employee
msg["Subject"] = "🚨 URGENT: Your PayPal account has been limited"

# HTML body containing a known malicious Safe Browsing URL
body = """
<html>
  <body style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px;">
    <div style="border: 1px solid #ddd; padding: 20px; border-radius: 6px;">
      <h2 style="color: #d35400;">Security Notification</h2>
      <p>Dear Customer,</p>
      <p>We detected suspicious login attempts on your account from an unrecognized device.</p>
      <p>For your security, we have temporarily restricted access to your account. To lift this restriction, please verify your details immediately by clicking the link below:</p>
      
      <p style="text-align: center; margin: 30px 0;">
        <a href="http://testsafebrowsing.appspot.com/s/phishing.html" 
           style="background-color: #0070ba; color: white; padding: 12px 24px; text-decoration: none; font-weight: bold; border-radius: 4px;">
           Verify Account Details
        </a>
      </p>
      
      <p>If this verification is not completed within 24 hours, your account will be suspended permanently.</p>
      <p>Sincerely,<br>PayPal Security & Risk Operations</p>
    </div>
  </body>
</html>
"""
msg.attach(MIMEText(body, "html"))

# --- Send email to Mailtrap SMTP ---
try:
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(USERNAME, PASSWORD)
        server.sendmail(msg["From"], msg["To"], msg.as_string())
    print("✅ Phishing test email successfully sent to your Mailtrap inbox!")
    print("👉 Log in to mailtrap.io to see the incoming message, then run your PhishGuard scan.")
except Exception as e:
    print(f"❌ Failed to send email: {e}")

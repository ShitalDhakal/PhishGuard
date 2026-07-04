import smtplib
import os
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from Mailbox.models import MailBox


def sendEmail(address, subject, body):
    
    mailbox = MailBox.objects.first()
    try:
        with smtplib.SMTP_SSL(mailbox.imap_server, 465) as server:
            server.login(mailbox.address, mailbox.app_password)
            msg = MIMEMultipart()
            msg['From'] = mailbox.address
            msg['To'] = address
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            server.send_message(msg)
        print(f"Email sent to {address}")
    except Exception as e:
        print(f"Failed to send email: {e}")
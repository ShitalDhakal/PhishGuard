from django.db import models


class EmailRecord(models.Model):
    """
    Stores every email fetched from the monitored mailbox via IMAP.
    Each row = one email that PhishGuard has ingested for analysis.
    """

    # IDENTIFIERS
    uid = models.CharField(max_length=255, unique=True)           # IMAP UID — permanent ID within the mailbox
    message_id = models.TextField(null=True, blank=True)          # Message-ID header — globally unique per email

    #  HEADERS
    sender = models.TextField(null=True, blank=True)              # From
    recipient = models.TextField(null=True, blank=True)           # To
    cc = models.TextField(null=True, blank=True)                  # CC
    bcc = models.TextField(null=True, blank=True)                 # BCC
    subject = models.TextField(null=True, blank=True)             # Subject
    date = models.CharField(max_length=255, null=True, blank=True)  # Date header (kept as string — email dates can be malformed)
    reply_to = models.TextField(null=True, blank=True)            # Reply-To (often spoofed in phishing)
    return_path = models.TextField(null=True, blank=True)         # Return-Path (envelope sender)
    x_mailer = models.TextField(null=True, blank=True)            # X-Mailer — reveals sending software

    #  AUTHENTICATION HEADERS
    received_spf = models.TextField(null=True, blank=True)        # SPF result (pass/fail/softfail)
    dkim_signature = models.TextField(null=True, blank=True)      # DKIM signature header
    dmarc = models.TextField(null=True, blank=True)               # DMARC result
    received_chain = models.JSONField(null=True, blank=True)      # All "Received:" headers as a list — shows the email's path

    #  BODY
    body_text = models.TextField(null=True, blank=True)           # text/plain body
    body_html = models.TextField(null=True, blank=True)           # text/html body

    #  RAW DATA
    raw_email = models.BinaryField(null=True, blank=True)         # Full RFC822 bytes — allows re-analysis without re-fetching

    #  METADATA
    source_folder = models.CharField(max_length=255, default="INBOX")  # Which IMAP folder this email came from
    is_multipart = models.BooleanField(default=False)             # True if email has multiple MIME parts
    has_attachments = models.BooleanField(default=False)           # True if attachments were found
    fetched_at = models.DateTimeField(auto_now_add=True)          # When PhishGuard ingested this email
    score = models. IntegerField()
    scanned = models.BooleanField(default=False)

    class Meta:
        ordering = ["-fetched_at"]                                # Newest emails first

    def __str__(self):
        return f"[{self.uid}] {self.subject or '(no subject)'} — from {self.sender or 'unknown'}"


class EmailAttachment(models.Model):
    """
    Stores each attachment extracted from an email.
    One EmailRecord can have zero or many attachments (one-to-many).
    """

    email = models.ForeignKey(
        EmailRecord,
        on_delete=models.CASCADE,                                 # Delete attachments when the parent email is deleted
        related_name="attachments"                                # Access via: email_record.attachments.all()
    )
    filename = models.TextField(null=True, blank=True)            # Original filename (e.g., "invoice.pdf")
    content_type = models.CharField(max_length=255)               # MIME type (e.g., "application/pdf")
    size = models.IntegerField(null=True, blank=True)             # File size in bytes
    file_hash = models.CharField(max_length=64, null=True, blank=True)  # SHA-256 hash — for threat intel lookups
    content = models.BinaryField(null=True, blank=True)           # Actual file bytes

    def __str__(self):
        return f"{self.filename or 'unnamed'} ({self.content_type}) — {self.size or 0} bytes"
    
    
class MailBox(models.Model):
    def __str__(self):
        return self.address
    
    mail_id = models.AutoField(primary_key=True)
    address = models.CharField(max_length=250)
    app_password = models.CharField(max_length=250)
    imap_server = models.CharField(max_length=250)
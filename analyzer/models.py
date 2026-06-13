from django.db import models
from Mailbox.models import EmailRecord

# Create your models here.
class IOC(models.Model):
    """
        Stores individual Indicators of Compromise (IOCs) extracted from analyzed emails.
    """
    IOC_TYPES = [
        ('url', 'URL'),
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('email', 'Email Address')
    ]

    # creates a Foreign Key in the database, establishing that one email can have many IOC
    # Each IOC row points back to the ID of a single EmailRecord.
    email_record = models.ForeignKey(
        EmailRecord,
        # controls what happens to the IOC records when the parent email is deleted from PhishGuard.
        on_delete = models.CASCADE,
        related_name="iocs"
    )

    # Type of indicator (e.g. url, ip, domain, email)
    ioc_type = models.CharField(max_length=10, choices=IOC_TYPES)

    # The value of IOC
    value = models.TextField()  # phishing URLs can be extremely long, that's why textfiedl


    # store where the IOC was found, e.g body, header, url
    source = models.CharField(max_length=50)

    is_malicious = models.BooleanField(default=None, blank= True, null = True)

    # This stores the raw numerical reputation score returned by threat intelligence APIs.
    # AbuseIPDB: Returns an Abuse Confidence Score from 0 to 100
    # VirusTotal: Returns the Number of Malicious Detections
    threat_score = models.IntegerField(default=None, blank = True, null = True)

    # Timestamp when this was recorded
    detected_at = models.DateTimeField(auto_now_add=True)

    class Meta:

        # sets the default query sorting order for this model.
        ordering = ["-detected_at"] # The minus sign (-) stands for descending order (newest first).
        #  Ensure we do not store duplicate IOCs of the same type/value for the same email
        unique_together = ('email_record', 'ioc_type', 'value')

    def __str__(self):
        return f"[{self.ioc_type.upper()}] {self.value} (Source: {self.source})"
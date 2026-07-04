from django.db import models
from Mailbox.models import EmailRecord
from django.core.validators import MinValueValidator, MaxValueValidator

# Create your models here.
class IOC(models.Model):
    """
        Stores individual Indicators of Compromise (IOCs) extracted from analyzed emails.
    """
    IOC_TYPES = [
        ('url', 'URL'),
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('email', 'Email Address'),
        ('hash', 'File Hash'),
    ]

    # creates a Foreign Key in the database, establishing that one email can have many IOC
    # Each IOC row points back to the ID of a single EmailRecord.

    email_ids = models.CharField(max_length=1000)

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

    file_hash = models.CharField(null=True, blank=True)

    class Meta:

        # sets the default query sorting order for this model.
        ordering = ["-detected_at"] # The minus sign (-) stands for descending order (newest first).
        #  Ensure we do not store duplicate IOCs of the same type/value for the same email
        unique_together = ('ioc_type', 'value')

    def __str__(self):
        return f"[{self.ioc_type.upper()}] {self.value} (Source: {self.source})"
    
class AnalysisReport(models.Model):

    VERDICT_CHOICES = [
        ("Safe" ,"Safe"),
        ("Suspicious", "Suspicious"),
        ("Malicious", "Malicious")
    ]


    CLASSIFICATION_CHOICES = [
        ('Clean', 'Clean'),
        ('Spam', 'Spam'),
        ('Phishing', 'Phishing'),
    ]

    email_id = models.ForeignKey(EmailRecord, on_delete=models.CASCADE)
    overall_risk_score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(100)], default = 0)
    verdict =  models.CharField(max_length=20, choices=VERDICT_CHOICES, default="Safe")
    classification = models.CharField(max_length=20, choices=CLASSIFICATION_CHOICES, default="Clean")
    phising_type = models.CharField(max_length=50, null=True)
    ioc_risk_score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(100)], default = 0)
    ml_risk_score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(100)], default = 0)
    authentication_risk_score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(100)], default = 0)
    analyst_notes = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"] # for showing newest data

    def __str__(self):
        return f"Analysis Report for Email ID: {self.email_id.id} - Verdict: {self.verdict}, Classification: {self.classification}"
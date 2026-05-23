from django.db import models

# Create your models here.

class MailBox(models.Model):
    def __str__(self):
        return self.address
    
    mail_id = models.AutoField(primary_key=True)
    address = models.CharField(max_length=250)
    app_password = models.CharField(max_length=250)
    imap_server = models.CharField(max_length=250)
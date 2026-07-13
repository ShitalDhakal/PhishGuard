from django.db import models
from django.utils import timezone
# Create your models here.


class User(models.Model):

    user_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=250)
    email = models.CharField(max_length=250)
    password = models.CharField(max_length=1000)
    role = models.CharField(max_length=250)
    created_date = models.DateTimeField(default=timezone.now)
    modified_date = models.DateTimeField(default=timezone.now)


    
    def __str__(self):
        return self.username
    
class EsewaPayment(models.Model):
    is_paid = models.BooleanField(default=False)

    def __str__(self):
        return f"Payment {self.payment_id} - User: {self.user.username} - Amount: {self.amount} - Status: {self.status}"
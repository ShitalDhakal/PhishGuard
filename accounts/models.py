from django.db import models
from django.utils import timezone
# Create your models here.



class Role(models.Model):
    def __str__(self):
        return self.role_name
    
    role_id = models.IntegerField(primary_key=True)
    role_name = models.CharField(max_length=50)

class User(models.Model):
    
    def __str__(self):
        return self.username
    
    user_id = models.IntegerField(primary_key=True)
    username = models.CharField(max_length=250)
    email = models.CharField(max_length=250)
    password = models.CharField(max_length=1000)
    role_id = models.ForeignKey(Role, on_delete=models.CASCADE)
    created_date = models.DateTimeField(default=timezone.now)
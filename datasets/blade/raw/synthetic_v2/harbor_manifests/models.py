from django.db import models
from django.contrib.auth.models import User

class Record(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    tenant_id = models.CharField(max_length=64)
    group_id = models.CharField(max_length=64)
    value = models.TextField()

class Membership(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    group_id = models.CharField(max_length=64)
    class Meta:
        unique_together = ("user", "group_id")

from django.db import models
from django.db import models

class SecurityLogEntry(models.Model):
    sequence_number = models.BigIntegerField(unique=True)
    payload = models.JSONField()
    backend_signature = models.BinaryField()
    server_signature = models.BinaryField()
    previous_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['sequence_number']

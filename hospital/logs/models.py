from django.db import models

class OutgoingSecurityLog(models.Model):
    payload = models.BinaryField()  # store encrypted payload
    server_sequence_number = models.BigIntegerField(null=True, blank=True)
    server_signature = models.BinaryField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

class StandardLogEntry(models.Model):
    payload = models.JSONField()  # raw log data
    tentative_sequence_number = models.BigIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

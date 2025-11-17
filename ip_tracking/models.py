# ip_tracking/models.py
from django.db import models

class RequestLog(models.Model):
    """
    Model to store basic request metadata for auditing and analytics.
    """
    ip_address = models.GenericIPAddressField(
        verbose_name="IP Address",
        null=True, 
        blank=True
    )
    path = models.CharField(
        verbose_name="Request Path",
        max_length=255
    )
    timestamp = models.DateTimeField(
        verbose_name="Timestamp",
        auto_now_add=True
    )

    class Meta:
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {self.ip_address} - {self.path}"
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
    
    country = models.CharField(
        max_length=100, 
        null=True, 
        blank=True
    )
    city = models.CharField(
        max_length=100, 
        null=True, 
        blank=True
    )

    class Meta:
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.timestamp.strftime('%H:%M:%S')}] {self.ip_address} ({self.city}, {self.country}) - {self.path}"
    

class BlockedIP(models.Model):
    """
    Model to store IP addresses that should be blocked from accessing the site.
    """
    ip_address = models.GenericIPAddressField(
        verbose_name="IP Address",
        unique=True,
    )
    
    reason = models.CharField(
        max_length=255, 
        blank=True, 
        default="General Blacklist"
    )
    created_at = models.DateTimeField(
        auto_now_add=True
    )

    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.ip_address} (Reason: {self.reason})"


class SuspiciousIP(models.Model):
    """
    Model to flag IP addresses exhibiting anomalous behavior.
    """
    ip_address = models.GenericIPAddressField(
        verbose_name="IP Address",
        unique=True
    )
    reason = models.TextField(
        verbose_name="Reason for Flagging"
    )
    flagged_at = models.DateTimeField(
        auto_now_add=True
    )

    class Meta:
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        ordering = ['-flagged_at']

    def __str__(self):
        return f"{self.ip_address} - {self.reason[:50]}"
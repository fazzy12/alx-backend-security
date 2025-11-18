from celery import shared_task
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta
from .models import RequestLog, SuspiciousIP

@shared_task
def detect_anomalies():
    """
    Detects anomalies based on high request volume and access to sensitive paths 
    over the last one hour.
    """
    logger = detect_anomalies.get_logger()
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)
    

    high_volume_ips = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).values(
        'ip_address'
    ).annotate(
        request_count=Count('ip_address')
    ).filter(
        request_count__gt=100,
        ip_address__isnull=False
    ).values_list('ip_address', flat=True)

    for ip in high_volume_ips:
        SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            defaults={
                'reason': f"Exceeded high volume threshold ({RequestLog.objects.filter(ip_address=ip, timestamp__gte=one_hour_ago).count()} requests) in the last hour."
            }
        )
        logger.warning(f"Flagged High Volume IP: {ip}")
        
    
    
    sensitive_paths = ['/admin', '/login']
    
    sensitive_path_ips = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago,
        path__in=sensitive_paths
    ).values_list('ip_address', flat=True).distinct()

    for ip in sensitive_path_ips:

        count = RequestLog.objects.filter(ip_address=ip, timestamp__gte=one_hour_ago, path__in=sensitive_paths).count()
        
        if count > 10:
             SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                defaults={
                    'reason': f"Repeated sensitive path access ({count} attempts to {', '.join(sensitive_paths)}) in the last hour."
                }
            )
             logger.warning(f"Flagged Sensitive Access IP: {ip}")
             
    logger.info("Anomaly detection task completed.")
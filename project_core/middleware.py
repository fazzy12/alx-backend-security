# ip_tracking/middleware.py
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP
from django.utils import timezone
import threading
import logging

logger = logging.getLogger(__name__)

BLOCKED_IP_CACHE = set()
CACHE_LAST_UPDATED = None
CACHE_TTL_SECONDS = 300

class BasicIPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)


        threading.Thread(target=self._log_request, args=(request,)).start()

        return response

    def _get_client_ip(self, request):
        """
        Tries to get the client's IP address. 
        In production, a library like django-ipware is recommended.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
            
        return ip

    def _log_request(self, request):
        """
        The actual function that creates the RequestLog entry.
        """
        try:
            ip_address = self._get_client_ip(request)
            path = request.path
            
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path,
            )
            logger.debug(f"Logged request: IP={ip_address}, Path={path}")
            
        except Exception as e:
            logger.error(f"Error logging request: {e}", exc_info=True)
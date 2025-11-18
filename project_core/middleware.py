# ip_tracking/middleware.py
from django.http import HttpResponseForbidden
from django.core.cache import caches
from django.conf import settings
from .models import RequestLog, BlockedIP
from django.utils import timezone
import threading
import logging
import ipinfo

logger = logging.getLogger(__name__)

geo_cache = caches['geolocation_cache'] 


def get_geolocation_data(ip_address):
    """
    Retrieves and caches geolocation data for a given IP address.
    Cache timeout is set in settings.py (24 hours).
    """
    cached_data = geo_cache.get(ip_address)
    if cached_data:
        return cached_data

    if ip_address in ['127.0.0.1', '::1'] or ip_address.startswith('192.168.'):
        return {'country': 'Localhost', 'city': 'N/A'}
    
    try:
        handler = ipinfo.getHandler(settings.IPINFO_API_TOKEN)
        
        details = handler.getDetails(ip_address)
        
        data = {
            'country': details.country_name,
            'city': details.city,
        }
        
        geo_cache.set(ip_address, data, timeout=settings.CACHES['geolocation_cache']['TIMEOUT'])
        
        return data

    except Exception as e:
        logger.error(f"IPinfo Geolocation Error for {ip_address}: {e}")
        return {'country': None, 'city': None}


class BasicIPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self._refresh_ip_cache()

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
            
        return ip
    
    def _refresh_ip_cache(self):
        global BLOCKED_IP_CACHE, CACHE_LAST_UPDATED
        if CACHE_LAST_UPDATED is None or (timezone.now() - CACHE_LAST_UPDATED).total_seconds() > CACHE_TTL_SECONDS:
            BLOCKED_IP_CACHE = set(BlockedIP.objects.values_list('ip_address', flat=True))
            CACHE_LAST_UPDATED = timezone.now()
            logger.info(f"Refreshed Blocked IP cache. Total IPs: {len(BLOCKED_IP_CACHE)}")


    def __call__(self, request):
        ip_address = self._get_client_ip(request)
        
        self._refresh_ip_cache() 
        if ip_address in BLOCKED_IP_CACHE:
            logger.warning(f"Blocking blacklisted IP: {ip_address} for path {request.path}")
            return HttpResponseForbidden("<h1>403 Forbidden: Access Denied</h1><p>Your IP address has been blocked.</p>")

        response = self.get_response(request)


        threading.Thread(target=self._log_request, args=(request, ip_address)).start()

        return response
        
    def _log_request(self, request, ip_address):
        """The actual function that creates the RequestLog entry, including geolocation."""
        try:
            geo_data = get_geolocation_data(ip_address)

            RequestLog.objects.create(
                ip_address=ip_address,
                path=request.path,
                country=geo_data.get('country'),
                city=geo_data.get('city'),
            )
            logger.debug(f"Logged request: IP={ip_address}, City={geo_data.get('city')}")
            
        except Exception as e:
            logger.error(f"Error logging request with geolocation: {e}", exc_info=True)
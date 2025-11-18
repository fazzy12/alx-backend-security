# ip_tracking/views.py
from django.shortcuts import render
from django.http import HttpResponse
from ratelimit.decorators import ratelimit
from django.contrib.auth.decorators import login_required, user_passes_test

def is_anonymous(user):
    """Custom function to check if a user is anonymous."""
    return not user.is_authenticated

@ratelimit(key='ip', rate='5/m', block=True, method=ratelimit.ALL, group='anonymous_limit', when=is_anonymous)
@ratelimit(key='ip', rate='10/m', block=True, method=ratelimit.ALL, group='authenticated_limit')
def sensitive_login_view(request):
    """
    A view simulating a login or API endpoint with differential rate limiting.
    
    If the user is logged in, the 10/m limit applies.
    If the user is anonymous, the 5/m limit applies.
    The 'key="ip"' ensures the limit is tracked by the client's IP address.
    """
    if request.user.is_authenticated:
        status = f"Authenticated User: {request.user.username}"
    else:
        status = "Anonymous User"
        
    return HttpResponse(f"<h1>Login Page/API Endpoint</h1><p>Welcome, {status}. Request accepted.</p>")
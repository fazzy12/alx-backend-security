from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.sensitive_login_view, name='sensitive_login'),
]
from django.urls import path
from . import views

app_name = "api"

urlpatterns = [
    path('sign/', views.log_security_entry, name='upload_page'),
]
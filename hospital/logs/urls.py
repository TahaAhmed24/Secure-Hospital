from django.urls import path
from . import views

app_name = "logs"

urlpatterns = [
    path('security',views.send_security_log , name='log_security'),
    path('standard',views.log_standard_entry , name='log_standard'),
]
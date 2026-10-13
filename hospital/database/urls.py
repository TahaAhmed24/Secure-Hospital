from django.urls import path
from . import api_views

app_name = "appointments"

urlpatterns = [
    # Profile endpoints
    path('api/profile/', api_views.get_profile, name='get_profile'),
    path('api/profile/update/', api_views.update_profile, name='update_profile'),

    # For patients
    path('api/doctors/available/', api_views.list_available_doctors, name='list_available_doctors'),
    path('api/doctors/appointed/', api_views.my_doctors, name='my_doctors'),
    path('api/doctors/pending/', api_views.pending_appointment_requests, name='pending_appointment_requests'),
    path('api/doctors/add/', api_views.send_appointment_request, name='add_doctor'),
    path('api/doctors/remove/', api_views.remove_doctor, name='remove_doctor'),
    path('api/requests/respond/', api_views.respond_to_request, name='respond_to_request'),

    # For doctors
    path('api/patients/available/', api_views.list_available_patients, name='list_available_patients'),
    path('api/patients/appointed/', api_views.my_patients, name='my_patients'),
    path('api/patients/pending/', api_views.pending_patients_requests, name='pending_patients_requests'),
    path('api/requests/send/', api_views.send_appointment_request, name='send_request'),
]

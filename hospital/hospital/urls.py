"""example URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from hospital import views
from hospital.forms import (
    StyledAuthenticationForm,
    StyledPasswordChangeForm,
    StyledPasswordResetForm,
    StyledSetPasswordForm,
)


auth_urlpatterns = [
    path(
        "login/",
        views.RoleLoginView.as_view(),
        name="login",
    ),

    path(
        "logout/",
        auth_views.LogoutView.as_view(template_name="accounts/logged_out.html"),
        name="logout",
    ),
]

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include(auth_urlpatterns)),
    path("", views.home, name="home"),
    path("setup/", views.SetupView.as_view(), name="setup"),
    path("setup/keys/", views.SetupKeysView.as_view(), name="setup_keys"),
    path("setup/device/", views.SetupDeviceView.as_view(), name="setup_device"),
    path("devices/", views.DevicesView.as_view(), name="devices"),
    path("my-doctors/", views.PatientDoctorsView.as_view(), name="patient_doctors"),
    path("my-patients/", views.DoctorPatientsView.as_view(), name="doctor_patients"),
    path("medical-records/", views.MedicalRecordsView.as_view(), name="medical_records"),
    path("medical-records/<int:file_id>", views.MedicalRecordView.as_view(), name="medical_record"),
    # private page only accessible once you are logged in with webauthn
    path("private/", views.private, name="private"),
    path("profile/", views.ProfileView.as_view(), name="profile"),
    path("register/", views.RegisterView.as_view(), name="register"),
    path("webauth/", include("authentication.urls")),
    path("records/", include("documentSigning.urls")),
    path("appointments/", include("database.urls")),
    path("logs/", include("logs.urls")),
]

from django.urls import path

from authentication.views_access import login,registration,devices


app_name = "webauth"
urlpatterns = [
    path("devices/", devices.DeviceListView.as_view(), name="devices"),
    path("devices/<int:pk>/delete/", devices.DeleteDevice.as_view(), name="delete"),
    path("register_device", devices.RegisterDevice.as_view(), name="register_device"),
    path("registration/", registration.Registration.as_view(), name="registration"),
    path('begin_login/', login.begin_login, name='begin_login'),
    path('webauth_challenge/', login.webauthn_challenge, name='webauthn_challenge'),
    path('webauth_verify/', login.webauthn_verify, name='webauthn_verify'),
    path('certificates/renew/', login.renew_certificate_page, name='renew_certificate_page'),
    path('renewCertificate/', login.renew_certificate_view, name='renew_certificate'),
]

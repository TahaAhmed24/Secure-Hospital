import json

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.urls import reverse_lazy
from django.views import View
from django.views.generic.edit import DeleteView
from django.views.generic.list import ListView
from webauthn import (
    verify_registration_response,
)
from webauthn.helpers.structs import (
    RegistrationCredential,
    AuthenticatorAttestationResponse,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, generate_challenge


from authentication.models import WebAuthDevice


class DeviceListView(ListView, LoginRequiredMixin):
    model = WebAuthDevice

    def get_queryset(self):
        qs = super().get_queryset()
        qs = qs.filter(user=self.request.user)
        return qs


class DeleteDevice(DeleteView):
    model = WebAuthDevice
    success_url = reverse_lazy("webauth:devices")

    def get_queryset(self):
        qs = super().get_queryset()
        qs = qs.filter(user=self.request.user)
        return qs

class RegisterDevice(View):
    """
    Passwordless registration flow for a new user.
    Step 1: submit username (optional form)
    Step 2: create WebAuthn key
    """

    def get(self, request, *args, **kwargs):
        """
        Returns a WebAuthn challenge for the new user.
        The frontend must send a username in query params or session.
        """
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required"}, status=401)
        username = request.user.username
        # Challenge for WebAuthn
        challenge = generate_challenge()
        request.session["webauth_challenge"] = bytes_to_base64url(challenge)
        user_id = username.encode("utf-8")  # using username as user_id for now

        return JsonResponse(
            {
                "publicKey": {
                    "rp": {
                        "id": settings.WEBAUTH_RP_ID,
                        "name": settings.WEBAUTH_RP_NAME,
                    },
                    "user": {
                        "id": bytes_to_base64url(user_id),
                        "name": username,
                        "displayName": username,
                    },
                    "pubKeyCredParams": [
                        {"type": "public-key", "alg": -7},
                        {"type": "public-key", "alg": -257},
                    ],
                    "attestation": "direct",
                    "timeout": 60000,
                    "challenge": bytes_to_base64url(challenge),
                }
            }
        )

    def post(self, request, *args, **kwargs):
        """
        Finalizes registration: creates User and WebAuthDevice.
        """
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required"}, status=401)
        
        challenge = base64url_to_bytes(request.session.pop("webauth_challenge", None))
        username = request.session.pop("register_username", None)

        if not challenge or not username:
            return JsonResponse({"error": "Session expired"}, status=400)

        data = json.loads(request.body)
        credential_data = data.get("pubKeyCredential")
        name = data.get("name", "My Security Key") #fallback if no name

        # Build RegistrationCredential
        credential = RegistrationCredential(
            id=credential_data["id"],
            raw_id=base64url_to_bytes(credential_data["rawId"]),
            response=AuthenticatorAttestationResponse(
                client_data_json=base64url_to_bytes(credential_data["response"]["clientDataJSON"]),
                attestation_object=base64url_to_bytes(credential_data["response"]["attestationObject"]),
            ),
            type=credential_data["type"],
        )

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=settings.WEBAUTH_ORIGIN,
            expected_rp_id=settings.WEBAUTH_RP_ID,
            require_user_verification=False,
        )
        # Save WebAuthDevice with public key and identifier
        WebAuthDevice.objects.create(
            user=request.user,
            name=name,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            format=verification.fmt,
            type=verification.credential_type,
            sign_count=verification.sign_count,
        )

        return JsonResponse({"status": "ok"})

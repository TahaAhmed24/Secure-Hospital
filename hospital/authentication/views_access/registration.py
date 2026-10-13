
import base64
import json

from django.conf import settings
from django.contrib.auth.models import User
from django.http import (
    JsonResponse,
)
from django.views import View

from webauthn import (
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    generate_challenge,
)
from webauthn.helpers.structs import (
    AuthenticatorAttestationResponse,
    RegistrationCredential,
)

from authentication.models import WebAuthDevice
from authentication.utils.certificate_handling import (
    issue_doctor_certificate,
)
from database.models import Doctor, Patient




class Registration(View):
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
        username = request.GET.get("username")
        role = request.GET.get("role")
        print(username,role)
        if not username:
            return JsonResponse({"error": "Username required"}, status=400)
        if role not in ["doctor", "patient"]:
            return JsonResponse({"error": "Invalid role"}, status=400)

        # Check if username already exists
        if User.objects.filter(username=username).exists():
            return JsonResponse({"error": "Username already taken"}, status=400)

        # Save username in session temporarily
        request.session["register_username"] = username
        request.session['role'] = role

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
        challenge = base64url_to_bytes(request.session.pop("webauth_challenge", None))
        username = request.session.pop("register_username", None)

        if not challenge or not username:
            return JsonResponse({"error": "Session expired"}, status=400)

        data = json.loads(request.body)
        print("POST data:", data)
        credential_data = data.get("pubKeyCredential")
        name = data.get("name", "My Security Key")

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

        # Create the actual User
        role = request.session.pop("role")

        user = User.objects.create_user(username=username)

        if role == 'doctor':
            Doctor.objects.create(
                user=user
            )
        else:
            Patient.objects.create(
                user=user
            )

        user.set_unusable_password()
        user.save()

        # Save WebAuthDevice with public key and identifier
        WebAuthDevice.objects.create(
            user=user,
            name=name,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            format=verification.fmt,
            type=verification.credential_type,
            sign_count=verification.sign_count,
        )
        
        if role == 'doctor':
            # Get both p12 data and password
            p12_data, cert_password = issue_doctor_certificate(user)
            return JsonResponse({
                "status": "ok",
                "certificate": base64.urlsafe_b64encode(p12_data).decode("utf-8"),
                "certificate_password": cert_password  # Send password to frontend
            })
        else:
            return JsonResponse({"status": "ok"})

# views.py
import json
import secrets
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.core.cache import cache
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from webauthn import verify_authentication_response
from webauthn.helpers.structs import AuthenticationCredential, AuthenticatorAssertionResponse, RegistrationCredential, AuthenticatorAttestationResponse
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, generate_challenge
from webauthn import verify_registration_response
from database.models import Doctor,Patient
from .models import WebAuthDevice
from http import HTTPStatus
import json
from django.conf import settings
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponse
from django.views import View

from .models import WebAuthDevice

def begin_login(request):
    """
    Step 1: User submits username/password (optional for passwordless)
    Server validates credentials, but does NOT create session yet.
    Returns a temporary token for 2FA.
    """
    if request.method != "POST":
        return HttpResponseBadRequest("Invalid method")

    username = request.POST.get("username")

    user = User.objects.filter(username=username).first()
    if not user:
        return JsonResponse({"error": "Invalid credentials"}, status=400)

    # Generate temporary 2FA token
    token = secrets.token_urlsafe(32)
    cache.set(f"2fa:{token}", user.pk, timeout=300) 

    return JsonResponse({"token": token})


def webauthn_challenge(request):
    """
    Step 2: Return WebAuthn challenge for temporary 2FA token
    """
    token = request.GET.get("token")
    user_pk = cache.get(f"2fa:{token}")
    if not user_pk:
        return JsonResponse({"error": "Invalid or expired token"}, status=400)

    user = User.objects.get(pk=user_pk)
    # create the challenge and set a timeout of 5 minutes
    challenge = generate_challenge()
    cache.set(f"webauth_challenge:{token}", bytes_to_base64url(challenge), timeout=300)
    # retrieve the credentials from the database
    credential_ids = WebAuthDevice.objects.filter(user=user).values_list("credential_id", flat=True)
    return JsonResponse({
        "publicKey": {
            "challenge": bytes_to_base64url(challenge),
            "allowCredentials": [
                {
                    "id": bytes_to_base64url(cred_id),
                    "type": "public-key",
                    "transports": ["usb", "ble", "nfc", "internal", "hybrid"],
                } for cred_id in credential_ids
            ],
            "timeout": 60000,
            "userVerification": "preferred",
        }
    })


@csrf_exempt
def webauthn_verify(request):
    """
    Step 3: Verify WebAuthn assertion and create session
    """
    data = json.loads(request.body)
    token = data.get("token")
    user_pk = cache.get(f"2fa:{token}")
    if not user_pk:
        return JsonResponse({"error": "Invalid token"}, status=400)

    user = User.objects.get(pk=user_pk)
    challenge_b64 = cache.get(f"webauth_challenge:{token}")
    if not challenge_b64:
        return JsonResponse({"error": "Challenge expired"}, status=400)

    challenge = base64url_to_bytes(challenge_b64)

    # Build AuthenticationCredential
    credential = AuthenticationCredential(
        id=data["id"],
        raw_id=base64url_to_bytes(data["rawId"]),
        response=AuthenticatorAssertionResponse(
            client_data_json=base64url_to_bytes(data["response"]["clientDataJSON"]),
            authenticator_data=base64url_to_bytes(data["response"]["authenticatorData"]),
            signature=base64url_to_bytes(data["response"]["signature"]),
            user_handle=base64url_to_bytes(data["response"]["userHandle"]) if data["response"].get("userHandle") else None,
        ),
        type=data["type"],
    )
    # Lookup device by raw_id
    try:
        device = WebAuthDevice.objects.get(credential_id=credential.raw_id)
    except WebAuthDevice.DoesNotExist:
        return JsonResponse({"error": "Device not registered"}, status=400)

    # Verify assertion
    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=settings.WEBAUTH_RP_ID,
        expected_origin=settings.WEBAUTH_ORIGIN,
        credential_public_key=device.public_key,
        credential_current_sign_count=device.sign_count,
        require_user_verification=True,
    )
    # Update device sign count
    device.sign_count = verification.new_sign_count
    device.save()
    # Cleanup temporary token

    # Successful → create real session
    login(request, user)
    
    # Determine the role
    if hasattr(user, "doctor_profile"):
        request.session["role"] = "doctor"
    elif hasattr(user, "patient_profile"):
        request.session["role"] = "patient"
        
    # Store device ID in session for auth_status()
    request.session["webauth_device_id"] = device.id
    cache.delete(f"2fa:{token}")
    cache.delete(f"webauth_challenge:{token}")
    return HttpResponse()




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

        return JsonResponse({
            "status": "ok",
            "user_id": user.id,
            "redirect": "/accounts/login?next=/setup/keys/"
        })

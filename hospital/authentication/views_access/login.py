import json
import secrets

from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.core.cache import cache
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseForbidden,
    JsonResponse,
)
from django.views.decorators.csrf import csrf_exempt
from authentication.utils.certificate_handling import certificate_needs_renewal, renew_doctor_certificate

from django.contrib.auth.decorators import login_required
import base64
from django.shortcuts import render

# Third-party: WebAuthn
from webauthn import (
    verify_authentication_response
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    generate_challenge,
)
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorAssertionResponse
)

from authentication.models import WebAuthDevice
from authentication.utils.certificate_handling import (
    verify_certificate_chain,
)

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
    # After login(request, user)
    print(request.META.get("HTTP_X_SSL_CLIENT_CERT"))
    if hasattr(user, "doctor_profile"):
        client_cert_pem = request.META.get("HTTP_X_SSL_CLIENT_CERT")
        if not client_cert_pem:
            return HttpResponseForbidden("Doctor certificate required")
        else:
            needs_renewal, cert = certificate_needs_renewal(user)

            if needs_renewal:
                # generate a short-lived token for certificate renewal (e.g., 5 minutes)
                renewal_token = secrets.token_urlsafe(32)
                cache.set(f"cert_renew:{renewal_token}", user.pk, timeout=300)

                return JsonResponse({
                    "renewal_required": True,
                    "renewal_token": renewal_token
                }, status=403)

        # Verify against your CA chain
        valid, details = verify_certificate_chain(client_cert_pem, user.username)
        if not valid:
            return HttpResponseForbidden(f"Invalid certificate: {details}")
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

@csrf_exempt
def renew_certificate_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid method"}, status=405)

    data = json.loads(request.body)
    token = data.get("token")
    user_pk = cache.get(f"cert_renew:{token}")
    print(user_pk)
    if not user_pk:
        return JsonResponse({"error": "Invalid or expired token"}, status=403)

    user = User.objects.get(pk=user_pk)

    if not hasattr(user, "doctor_profile"):
        return JsonResponse({"error": "Forbidden"}, status=403)

    # issue new certificate
    p12, password = renew_doctor_certificate(user)

    # delete token so it cannot be reused
    cache.delete(f"cert_renew:{token}")

    return JsonResponse({
        "certificate": base64.urlsafe_b64encode(p12).decode("utf-8"),
        "password": password,
    })


def renew_certificate_page(request):
    # token comes via query parameter
    token = request.GET.get("token")
    user_pk = cache.get(f"cert_renew:{token}")
    print(user_pk)
    if not user_pk:
        return HttpResponseForbidden("Invalid or expired token")

    return render(request, "accounts/renew.html", {"renewal_token": token})

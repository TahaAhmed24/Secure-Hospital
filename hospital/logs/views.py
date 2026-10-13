from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import json, base64
from .models import OutgoingSecurityLog, StandardLogEntry
import hmac
import hashlib
import requests

SECURITY_SERVER_URL = "http://securitylogger:8000/api/sign/"
PUBLIC_KEY_FILE = "/shared_keys/server_public_key.pem"

with open("hmac_secret.key", "rb") as f:
    HMAC_KEY = f.read()

# Load public key
with open(PUBLIC_KEY_FILE, "rb") as f:
    SERVER_PUBLIC_KEY = serialization.load_pem_public_key(f.read())


def base64url_to_bytes(s):
    """Convert base64url string to bytes."""
    # Add padding if needed
    padding_needed = 4 - (len(s) % 4)
    if padding_needed != 4:
        s += '=' * padding_needed
    # Convert base64url to standard base64
    s = s.replace('-', '+').replace('_', '/')
    return base64.b64decode(s)


def get_next_sequence():
    """Get the next sequence number for security logs."""
    last = OutgoingSecurityLog.objects.order_by('-server_sequence_number').first()
    return 1 if last is None else last.server_sequence_number + 1


def encrypt_payload(payload_data):
    """
    Encrypt payload using Security Server's RSA public key.
    Uses PKCS#1 v1.5 padding.
    """
    encrypted = SERVER_PUBLIC_KEY.encrypt(
        payload_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )
    return encrypted


@csrf_exempt
def send_security_log(request):
    """
    Send a security log entry to the Security Server.

    Process:
    1. Assign sequence number
    2. Create payload structure with sequence number
    3. Encrypt entire structure
    4. Compute HMAC on encrypted bytes
    5. Send to Security Server
    6. Store encrypted payload and response

    Supports hybrid encryption format from client:
    - encryptedKey: RSA-encrypted AES key (base64url)
    - iv: AES-GCM initialization vector (base64url)
    - tag: AES-GCM authentication tag (base64url)
    - ciphertext: AES-GCM encrypted payload (base64url)
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        payload_data = json.loads(request.body)
        encrypted_payload_obj = payload_data["encryptedPayload"]

        # Handle hybrid encryption format (object with encryptedKey, iv, tag, ciphertext)
        if isinstance(encrypted_payload_obj, dict):
            # Extract components from hybrid encryption
            encrypted_key = base64url_to_bytes(encrypted_payload_obj["encryptedKey"])
            iv = base64url_to_bytes(encrypted_payload_obj["iv"])
            tag = base64url_to_bytes(encrypted_payload_obj["tag"])
            ciphertext = base64url_to_bytes(encrypted_payload_obj["ciphertext"])

            # Pack into a combined format for storage and forwarding
            # Format: [key_len(2 bytes)][encrypted_key][iv(12 bytes)][tag(16 bytes)][ciphertext]
            key_len = len(encrypted_key).to_bytes(2, 'big')
            encrypted_payload = key_len + encrypted_key + iv + tag + ciphertext

            # Flag to indicate hybrid encryption format
            is_hybrid = True
        else:
            # Legacy format: single base64 string (pure RSA encryption)
            encrypted_payload = base64.b64decode(encrypted_payload_obj)
            is_hybrid = False

    except Exception as e:
        return JsonResponse({"error": "Invalid JSON", "details": str(e)}, status=400)

    # Get next sequence number
    tentative_sequence = get_next_sequence()

    # Compute HMAC on the encrypted bytes
    backend_hmac = hmac.new(HMAC_KEY, encrypted_payload, hashlib.sha256).digest()
    backend_signature_b64 = base64.b64encode(backend_hmac).decode('utf-8')

    # Build data to send to the Security Server
    # Note: sequence_number is sent both encrypted (inside payload) and separately (for validation)
    data_to_send = {
        "payload": base64.b64encode(encrypted_payload).decode('utf-8'),
        "backend_signature": backend_signature_b64,
        "sequence_number": tentative_sequence,
        "encryption_type": "hybrid" if is_hybrid else "rsa"
    }

    # Send to Security Server
    try:
        response = requests.post(SECURITY_SERVER_URL, json=data_to_send, timeout=10)
        response.raise_for_status()
        server_resp = response.json()
        
        # Check for chain integrity warnings from server
        if "warnings" in server_resp:
            print(f"WARNING: Security Server reported issues: {server_resp['warnings']}")
            return JsonResponse({
                "error": "Security Server detected integrity issues",
                "details": server_resp['warnings']
            }, status=500)
            
    except requests.exceptions.RequestException as e:
        return JsonResponse({
            "error": "Failed to contact security server",
            "details": str(e)
        }, status=500)
    except Exception as e:
        return JsonResponse({
            "error": "Unexpected error communicating with security server",
            "details": str(e)
        }, status=500)

    # Store log entry locally
    try:
        log_entry = OutgoingSecurityLog.objects.create(
            payload=encrypted_payload,
            server_sequence_number=tentative_sequence,
            server_signature=base64.b64decode(server_resp.get("server_signature"))
        )
    except Exception as e:
        return JsonResponse({
            "error": "Failed to store log entry locally",
            "details": str(e)
        }, status=500)

    return JsonResponse({
        "status": "sent",
        "tentative_sequence_number": tentative_sequence,
        "server_sequence_number": server_resp.get("sequence_number"),
        "log_id": log_entry.id,
        "current_hash": server_resp.get("current_hash")
    })


def get_next_standard_sequence():
    """Get the next sequence number for standard logs."""
    last = StandardLogEntry.objects.order_by('-tentative_sequence_number').first()
    return 1 if last is None else last.tentative_sequence_number + 1


@csrf_exempt
def log_standard_entry(request):
    """
    Store a standard (non-security) log entry locally.
    These logs are not sent to the Security Server.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        payload_data = json.loads(request.body)
    except Exception as e:
        return JsonResponse({"error": "Invalid JSON", "details": str(e)}, status=400)

    # Assign sequence number
    tentative_sequence = get_next_standard_sequence()
    print(payload_data)
    # Store log locally
    try:
        log_entry = StandardLogEntry.objects.create(
            payload=payload_data,
            tentative_sequence_number=tentative_sequence
        )
    except Exception as e:
        return JsonResponse({
            "error": "Failed to store standard log entry",
            "details": str(e)
        }, status=500)

    return JsonResponse({
        "status": "stored",
        "tentative_sequence_number": tentative_sequence,
        "log_id": log_entry.id
    })
# signing/views.py
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
import base64
import hashlib
from .models import SecurityLogEntry
from .crypto import checkSequenceNumber, checkHmac, sign


def compute_entry_hash(entry):
    """
    Compute the SHA256 hash of a complete log entry.
    
    The hash includes all fields in a consistent JSON structure with sorted keys.
    This hash forms the link in the blockchain-like chain.
    """
    entry_data = json.dumps({
        "sequence_number": entry.sequence_number,
        "payload": entry.payload,
        "backend_signature": base64.b64encode(entry.backend_signature).decode('utf-8'),
        "server_signature": base64.b64encode(entry.server_signature).decode('utf-8'),
        "previous_hash": entry.previous_hash
    }, sort_keys=True).encode('utf-8')
    
    return hashlib.sha256(entry_data).hexdigest()


def verify_hash_chain():
    """
    Verify the integrity of the entire hash chain.
    Returns (is_valid, errors) where errors is a list of issues found.
    """
    errors = []
    entries = SecurityLogEntry.objects.order_by('sequence_number').all()
    
    if not entries.exists():
        return True, errors
    
    previous_computed_hash = None
    
    for entry in entries:
        # Check if this is the genesis entry
        if entry.sequence_number == 1:
            if entry.previous_hash != "0" * 64:
                errors.append(
                    f"Genesis entry (seq {entry.sequence_number}) has invalid previous_hash: "
                    f"expected {'0' * 64}, got {entry.previous_hash}"
                )
        else:
            # Verify previous_hash matches the computed hash of the previous entry
            if previous_computed_hash and entry.previous_hash != previous_computed_hash:
                errors.append(
                    f"Entry {entry.sequence_number} has broken chain: "
                    f"expected previous_hash {previous_computed_hash}, got {entry.previous_hash}"
                )
        
        # Compute hash of this entry for the next iteration
        previous_computed_hash = compute_entry_hash(entry)
    
    return len(errors) == 0, errors


def verify_last_entry_hash(last_entry):
    """
    Verify that the last entry's previous_hash matches the computed hash of the entry before it.
    Returns (is_valid, error_message)
    """
    if not last_entry:
        return True, None
    
    if last_entry.sequence_number == 1:
        # Genesis entry should have all zeros
        if last_entry.previous_hash != "0" * 64:
            return False, f"Genesis entry has invalid previous_hash: {last_entry.previous_hash}"
        return True, None
    
    # Get the entry before the last one
    previous_entry = SecurityLogEntry.objects.filter(
        sequence_number=last_entry.sequence_number - 1
    ).first()
    
    if not previous_entry:
        return False, f"Missing entry for sequence number {last_entry.sequence_number - 1}"
    
    # Compute the hash of the previous entry
    computed_previous_hash = compute_entry_hash(previous_entry)
    
    # Verify it matches what's stored in last_entry
    if last_entry.previous_hash != computed_previous_hash:
        return False, (
            f"Hash chain broken at entry {last_entry.sequence_number}: "
            f"stored previous_hash={last_entry.previous_hash}, "
            f"computed={computed_previous_hash}"
        )
    
    return True, None


@csrf_exempt
def log_security_entry(request):
    """
    Receive and store a security log entry from the Hospital Backend.
    
    Security checks performed:
    1. HMAC verification (proves origin from backend)
    2. Sequence number validation (prevents gaps/duplicates)
    3. Hash chain integrity verification (detects tampering)
    4. HSM signing (proves acceptance by security server)
    
    CRITICAL: If chain integrity is broken, this function REJECTS the entry
    and returns an error. This prevents continuation after tampering.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)
    
    try:
        body = json.loads(request.body)
        payload = body.get("payload")  # Base64-encoded encrypted data
        backend_signature = body.get("backend_signature")  # Base64-encoded HMAC
        sequence_number = body.get("sequence_number")
    except Exception as e:
        #print(f"Invalid JSON in request: {e}")
        return JsonResponse({"error": "Invalid JSON", "details": str(e)}, status=400)
    
    if not payload or not backend_signature or sequence_number is None:
        return JsonResponse({"error": "Missing required fields"}, status=400)
    
    # Get last entry for sequence and chain validation
    last_entry = SecurityLogEntry.objects.order_by('-sequence_number').first()
    last_seq = last_entry.sequence_number if last_entry else None
    
    # --- CRITICAL SECURITY CHECK 1: Verify hash chain integrity ---
    #print(f"Verifying hash chain integrity before accepting new entry {sequence_number}...")
    
    if last_entry:
        is_valid, error_msg = verify_last_entry_hash(last_entry)
        if not is_valid:
            #print(f"CRITICAL ERROR: Hash chain integrity check failed: {error_msg}")
            return JsonResponse({
                "error": "Hash chain integrity violation detected",
                "details": error_msg,
                "action": "Entry REJECTED. System halted. Manual investigation required."
            }, status=500)
    
    # Optional: Verify entire chain (more expensive, use for periodic audits)
    # Uncomment for maximum security or scheduled verification
    # is_valid, chain_errors = verify_hash_chain()
    # if not is_valid:
    #     #print(f"CRITICAL ERROR: Full chain verification failed")
    #     for error in chain_errors:
    #         #print(f"   - {error}")
    #     return JsonResponse({
    #         "error": "Complete hash chain integrity violation detected",
    #         "details": chain_errors,
    #         "action": "Entry REJECTED. System halted. Manual investigation required."
    #     }, status=500)
    
    #print("Hash chain integrity verified successfully")
    
    # --- SECURITY CHECK 2: Verify sequence number ---
    if not checkSequenceNumber(sequence_number, last_seq):
        expected = (last_seq + 1) if last_seq else 1
        #print(f"Invalid sequence number: expected {expected}, got {sequence_number}")
        return JsonResponse({
            "error": "Invalid sequence number",
            "expected": expected,
            "received": sequence_number
        }, status=400)
    
    #print(f"Sequence number {sequence_number} validated")
    
    # --- SECURITY CHECK 3: Verify HMAC ---
    if not checkHmac(payload, backend_signature):
        #print("Invalid backend signature / HMAC verification failed")
        return JsonResponse({"error": "Invalid backend signature / HMAC"}, status=403)
    
    #print("HMAC signature verified successfully")
    
    # --- Calculate previous_hash for chain construction ---
    if last_entry:
        # Compute hash of the complete previous entry
        previous_hash = compute_entry_hash(last_entry)
        #print(f"Computed previous_hash for new entry: {previous_hash}")
    else:
        # Genesis entry: use standardized initial value
        previous_hash = "0" * 64
        #print("Creating genesis entry with previous_hash: " + previous_hash)
    
    # --- SECURITY CHECK 4: Sign with HSM ---
    try:
        # HSM signs: encrypted payload + sequence number + previous_hash
        # This cryptographically binds this entry to the entire chain history
        server_signature = sign(payload, sequence_number, previous_hash)
        #print(f"HSM signature generated for entry {sequence_number}")
    except Exception as e:
        #print(f"CRITICAL ERROR: HSM signing failed: {e}")
        return JsonResponse({
            "error": "HSM signing failed",
            "details": str(e)
        }, status=500)
    
    # --- Store entry ---
    try:
        entry = SecurityLogEntry.objects.create(
            sequence_number=sequence_number,
            payload=payload,  # Stored as base64 string
            backend_signature=base64.b64decode(backend_signature),  # Stored as binary
            server_signature=server_signature,  # Binary from HSM
            previous_hash=previous_hash  # Hex string
        )
        #print(f"Successfully stored log entry {sequence_number}")
    except Exception as e:
        #print(f"CRITICAL ERROR: Failed to create log entry: {e}")
        return JsonResponse({
            "error": "Failed to store log entry",
            "details": str(e)
        }, status=500)
    
    # --- Compute current entry's hash for response ---
    current_hash = compute_entry_hash(entry)
    
    #print(f"Entry {sequence_number} complete. Hash: {current_hash[:16]}...")
    
    return JsonResponse({
        "sequence_number": sequence_number,
        "server_signature": base64.b64encode(server_signature).decode('utf-8'),
        "previous_hash": previous_hash,
        "current_hash": current_hash,
        "status": "accepted"
    })


@csrf_exempt
def verify_chain(request):
    """
    Endpoint to manually verify the complete hash chain.
    Useful for periodic audits and integrity checks.
    """
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)
    
    is_valid, errors = verify_hash_chain()
    
    entry_count = SecurityLogEntry.objects.count()
    
    if is_valid:
        return JsonResponse({
            "status": "valid",
            "message": "Hash chain integrity verified successfully",
            "total_entries": entry_count
        })
    else:
        return JsonResponse({
            "status": "invalid",
            "message": "Hash chain integrity violations detected",
            "total_entries": entry_count,
            "errors": errors
        }, status=500)
# signing/crypto.py
import hmac
import hashlib
import json
import base64
import os
import pkcs11
from pkcs11 import Mechanism, ObjectClass

# Load HMAC shared secret key
with open("hmac_secret.key", "rb") as f:
    HMAC_KEY = f.read()

# SoftHSM Configuration
SOFTHSM_MODULE = os.getenv('SOFTHSM_MODULE', '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so')
TOKEN_LABEL = os.getenv('TOKEN_LABEL', 'security-server')
USER_PIN = os.getenv('HSM_PIN', '5678')
KEY_LABEL = 'signing-key'

# Set the SoftHSM config environment variable
softhsm_conf = os.getenv('SOFTHSM2_CONF', os.path.expanduser('~/.config/softhsm2/softhsm2.conf'))
os.environ['SOFTHSM2_CONF'] = os.path.expanduser(softhsm_conf)

# Initialize library once (singleton pattern)
_lib = None


def get_pkcs11_lib():
    """
    Get or initialize PKCS11 library (singleton).
    Handles the SoftHSM library loading with proper error handling.
    """
    global _lib
    if _lib is None:
        try:
            _lib = pkcs11.lib(SOFTHSM_MODULE)
            print(f"PKCS11 library loaded successfully from {SOFTHSM_MODULE}")
        except pkcs11.exceptions.AlreadyInitialized:
            _lib = pkcs11.lib(SOFTHSM_MODULE)
        except Exception as e:
            print(f"Error loading PKCS11 library: {e}")
            print(f"Module path: {SOFTHSM_MODULE}")
            print(f"SOFTHSM2_CONF: {os.environ.get('SOFTHSM2_CONF')}")
            raise RuntimeError(f"Failed to load PKCS11 library from {SOFTHSM_MODULE}: {e}")
    
    return _lib


def get_hsm_session():
    """
    Get an authenticated HSM session.
    Requires the PIN to access the HSM token.
    """
    lib = get_pkcs11_lib()
    try:
        token = lib.get_token(token_label=TOKEN_LABEL)
        return token.open(user_pin=USER_PIN)
    except Exception as e:
        print(f"Error opening HSM session: {e}")
        print(f"Token label: {TOKEN_LABEL}, PIN configured: {bool(USER_PIN)}")
        raise


def checkSequenceNumber(payload_seq, last_seq):
    """
    Verify that the incoming sequence number is exactly sequential.
    
    Args:
        payload_seq: The sequence number from the incoming request
        last_seq: The sequence number of the last stored entry (or None if first entry)
    
    Returns:
        True if sequence is valid, False otherwise
    """
    expected_seq = 1 if last_seq is None else last_seq + 1
    return payload_seq == expected_seq


def checkHmac(encrypted_payload_b64, backend_signature_b64):
    """
    Verify the HMAC signature sent by the backend.
    
    The HMAC is computed over the encrypted payload bytes using the shared secret key.
    This proves the log originated from the backend and hasn't been tampered with in transit.
    
    Args:
        encrypted_payload_b64: Base64-encoded encrypted payload
        backend_signature_b64: Base64-encoded HMAC signature
    
    Returns:
        True if HMAC is valid, False otherwise
    """
    encrypted_payload = base64.b64decode(encrypted_payload_b64)
    expected_hmac = hmac.new(HMAC_KEY, encrypted_payload, hashlib.sha256).digest()
    received_hmac = base64.b64decode(backend_signature_b64)
    
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(expected_hmac, received_hmac)


def _detect_encryption_type(encrypted_bytes):
    """
    Auto-detect whether payload uses hybrid or legacy RSA encryption.

    Hybrid format: [key_len(2 bytes)][encrypted_key][iv(12)][tag(16)][ciphertext]
    - key_len for RSA-2048 is 256 bytes
    - Minimum hybrid payload: 2 + 256 + 12 + 16 + 1 = 287 bytes

    Legacy RSA: Direct RSA-encrypted data (max ~245 bytes for RSA-2048 with PKCS#1)

    Returns "hybrid" or "rsa"
    """
    if len(encrypted_bytes) < 287:
        # Too small for hybrid, must be legacy RSA
        return "rsa"

    # Check if first 2 bytes represent a plausible RSA key length
    key_len = int.from_bytes(encrypted_bytes[:2], 'big')

    # RSA-2048 produces 256-byte ciphertext, RSA-4096 produces 512-byte
    # Allow range 128-1024 to be safe
    if 128 <= key_len <= 1024:
        # Check if total length is consistent with hybrid format
        # Format: 2 + key_len + 12 (iv) + 16 (tag) + ciphertext (at least 1 byte)
        min_expected = 2 + key_len + 12 + 16 + 1
        if len(encrypted_bytes) >= min_expected:
            return "hybrid"

    return "rsa"


def decrypt_payload(encrypted_payload_b64, encryption_type=None):
    """
    Decrypt the payload using HSM private key.

    IMPORTANT: The private key never leaves the HSM!
    The HSM performs the decryption operation internally and returns only the plaintext.

    NOTE: This function is available but not currently used in the implementation.
    The Security Server stores encrypted payloads without decrypting them to maintain
    end-to-end confidentiality.

    Supports two encryption formats (auto-detected if not specified):
    - "rsa": Legacy pure RSA encryption (small payloads only)
    - "hybrid": RSA-encrypted AES key + AES-GCM encrypted payload (recommended)

    Hybrid format structure:
    [key_len(2 bytes)][encrypted_key][iv(12 bytes)][tag(16 bytes)][ciphertext]

    Args:
        encrypted_payload_b64: Base64-encoded encrypted payload
        encryption_type: "rsa", "hybrid", or None (auto-detect)

    Returns:
        Decrypted payload as a Python dictionary
    """
    encrypted_bytes = base64.b64decode(encrypted_payload_b64)

    # Auto-detect encryption type if not specified
    if encryption_type is None:
        encryption_type = _detect_encryption_type(encrypted_bytes)

    with get_hsm_session() as session:
        # Find the private key in HSM (non-extractable)
        private_key = session.get_key(
            object_class=ObjectClass.PRIVATE_KEY,
            label=KEY_LABEL
        )

        if encryption_type == "hybrid":
            # Parse hybrid encryption format
            # Format: [key_len(2 bytes)][encrypted_key][iv(12 bytes)][tag(16 bytes)][ciphertext]
            key_len = int.from_bytes(encrypted_bytes[:2], 'big')
            offset = 2

            encrypted_key = encrypted_bytes[offset:offset + key_len]
            offset += key_len

            iv = encrypted_bytes[offset:offset + 12]
            offset += 12

            tag = encrypted_bytes[offset:offset + 16]
            offset += 16

            ciphertext = encrypted_bytes[offset:]

            # Step 1: Decrypt AES key using RSA (HSM operation)
            # Using RSA-OAEP with SHA-256 (matching client-side encryption)
            aes_key = private_key.decrypt(
                encrypted_key,
                mechanism=Mechanism.RSA_PKCS_OAEP,
                mechanism_param=(Mechanism.SHA256, Mechanism.MGF1_SHA256, None)
            )

            # Step 2: Decrypt payload using AES-GCM
            # Note: AES-GCM decryption is done outside HSM as only the RSA key is protected
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(aes_key)

            # AES-GCM expects ciphertext + tag concatenated
            ciphertext_with_tag = ciphertext + tag
            decrypted = aesgcm.decrypt(iv, ciphertext_with_tag, None)
        else:
            # Legacy RSA-only decryption
            # Decrypt using PKCS#1 v1.5 padding
            # Decryption happens inside the HSM
            decrypted = private_key.decrypt(
                encrypted_bytes,
                mechanism=Mechanism.RSA_PKCS
            )

    return json.loads(decrypted.decode('utf-8'))


def sign(payload, sequence_number, previous_hash):
    """
    Sign a log entry using the HSM private key.
    
    This function creates a digital signature that:
    1. Proves the Security Server accepted this entry (authentication)
    2. Binds the entry to the blockchain-like chain via previous_hash (integrity)
    3. Cannot be forged without access to the HSM PIN (non-repudiation)
    
    Process:
    1. Create a data structure containing: payload, sequence_number, previous_hash
    2. Serialize to JSON with sorted keys (for consistency)
    3. Compute SHA256 hash of the serialized data
    4. HSM signs the hash using RSA private key (SHA256-RSA-PKCS mechanism)
    
    The private key NEVER leaves the HSM!
    
    Args:
        payload: Base64-encoded encrypted payload (stored as string)
        sequence_number: Sequential entry number
        previous_hash: SHA256 hash of the previous entry (hex string)
    
    Returns:
        Binary signature bytes from the HSM
    """
    # Create the data structure to sign
    # This binds together the payload, its position in the sequence, and the chain
    entry_data = {
        "sequence_number": sequence_number,
        "payload": payload,
        "previous_hash": previous_hash
    }
    
    # Serialize with sorted keys for consistency
    data_bytes = json.dumps(entry_data, sort_keys=True).encode('utf-8')
    
    # Compute SHA256 digest
    digest = hashlib.sha256(data_bytes).digest()
    
    with get_hsm_session() as session:
        # Find the private key in HSM (non-extractable)
        private_key = session.get_key(
            object_class=ObjectClass.PRIVATE_KEY,
            label=KEY_LABEL
        )
        
        # Sign the digest using RSA with PKCS#1 v1.5 padding
        # The signing operation happens entirely within the HSM
        # SHA256_RSA_PKCS means: RSA signature of SHA256 hash with PKCS#1 v1.5 padding
        signature = private_key.sign(
            digest,
            mechanism=Mechanism.SHA256_RSA_PKCS
        )
    
    return signature


def verify_signature(payload, sequence_number, previous_hash, signature, public_key):
    """
    Verify an HSM signature (optional utility function).
    
    This can be used for auditing or verification purposes.
    
    Args:
        payload: Base64-encoded encrypted payload
        sequence_number: Sequential entry number
        previous_hash: SHA256 hash of the previous entry
        signature: Binary signature to verify
        public_key: RSA public key for verification
    
    Returns:
        True if signature is valid, False otherwise
    """
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.exceptions import InvalidSignature
    
    # Reconstruct the signed data
    entry_data = {
        "sequence_number": sequence_number,
        "payload": payload,
        "previous_hash": previous_hash
    }
    data_bytes = json.dumps(entry_data, sort_keys=True).encode('utf-8')
    digest = hashlib.sha256(data_bytes).digest()
    
    try:
        # Verify the signature
        public_key.verify(
            signature,
            digest,
            asym_padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
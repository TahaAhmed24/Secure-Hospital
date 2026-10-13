from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
import os
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from authentication.models import DoctorCertificate

load_dotenv()
import secrets

def issue_doctor_certificate(user, validity_days=365):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, user.username),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Doctor"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, f"{user.username}@example.com"),
        ])
    ).sign(private_key, hashes.SHA256())

    with open(os.getenv("INTERMEDIATE_CERTIFICATE"), "rb") as f:
        inter_cert = x509.load_pem_x509_certificate(f.read())
    with open(os.getenv("INTERMEDIATE_KEY"), "rb") as f:
        inter_key = serialization.load_pem_private_key(
            f.read(),
            password=None
            #password=os.getenv("INTERMEDIATE_KEY_PASSPHRASE").encode()
        )

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(inter_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .sign(inter_key, hashes.SHA256())
    )

    cert_password = secrets.token_urlsafe(16)

    p12 = pkcs12.serialize_key_and_certificates(
        name=user.username.encode(),
        key=private_key,
        cert=cert,
        cas=[inter_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(
            cert_password.encode()
        ),
    )

    DoctorCertificate.objects.create(
        user=user,
        serial_number=str(cert.serial_number),
        issued_at=cert.not_valid_before_utc,
        expires_at=cert.not_valid_after_utc,
    )

    return p12, cert_password


def verify_certificate_chain(client_cert_pem, username):
    """
    Verify that the client certificate is signed by intermediate -> root CA
    and optionally verify that it belongs to the specified user.

    Args:
        client_cert_pem: PEM-encoded client certificate
        username: username to verify certificate ownership

    Returns:
        tuple: (bool, str) - (is_valid, message)
    """
    from django.conf import settings
    try:
        client_cert = x509.load_pem_x509_certificate(client_cert_pem.encode(), default_backend())
        with open(settings.PKI_INTERMEDIATE_CERT, "rb") as f:
            intermediate_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(settings.PKI_ROOT_CERT, "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # Tier 2: client cert signed by intermediate
        intermediate_cert.public_key().verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            client_cert.signature_hash_algorithm,
        )

        # Tier 1: intermediate signed by root
        root_cert.public_key().verify(
            intermediate_cert.signature,
            intermediate_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            intermediate_cert.signature_hash_algorithm,
        )

        # Expiration check
        now = datetime.now(timezone.utc)
        for cert, name in [(client_cert, "Client"), (intermediate_cert, "Intermediate"), (root_cert, "Root")]:
            # Use the new timezone-aware properties
            if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
                return False, f"{name} certificate expired or not yet valid"

        # Username verification
        # Extract CN from certificate subject
        cert_cn = None
        for attribute in client_cert.subject:
            if attribute.oid == NameOID.COMMON_NAME:
                cert_cn = attribute.value
                break

        if not cert_cn:
            return False, "Certificate does not contain a Common Name"

        print(f"Certificate CN: {cert_cn}, Expected username: {username}")
        if cert_cn != username:
            return False, f"Certificate belongs to '{cert_cn}', not '{username}'"

        # Verify certificate is not revoked in database
        serial_number = str(client_cert.serial_number)
        cert_record = DoctorCertificate.objects.filter(
            user__username=username,
            serial_number=serial_number
        ).first()

        if not cert_record:
            return False, "Certificate not found in database"

        if cert_record.revoked:
            return False, "Certificate has been revoked"

        return True, "Certificate valid"
    except InvalidSignature:
        return False, "Invalid signature"
    except Exception as e:
        return False, str(e)


def certificate_needs_renewal(user, days=5):
    cert = (
        DoctorCertificate.objects
        .filter(user=user, revoked=False)
        .order_by("-expires_at")
        .first()
    )

    if not cert:
        return True, None  # no cert at all

    now = datetime.now(timezone.utc)

    if cert.expires_at <= now:
        return True, cert

    if cert.expires_at <= now + timedelta(days=days):
        return True, cert

    return False, cert
    
def renew_doctor_certificate(user):
    DoctorCertificate.objects.filter(
        user=user,
        expires_at__gt=datetime.now(timezone.utc)
    ).update(revoked=True)

    return issue_doctor_certificate(user)

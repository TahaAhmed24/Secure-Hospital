from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from datetime import datetime


class CertificateVerificationMiddleware(MiddlewareMixin):
    """
    Middleware that verifies 3-tier certificate chain for ALL requests.
    If verification fails, blocks access to the site.
    """
    _server_cert_verified = None

    def process_request(self, request):
        # Skip verification for static/media files
        if request.path.startswith('/static/') or request.path.startswith('/media/'):
            return None
        
        # Verify certificate chain
        if self._server_cert_verified is None:
            verification_result = self.verify_certificate_chain()
            
            if not verification_result['valid']:
                print(f"Certificate verification failed: {verification_result['error']}")
                return HttpResponseForbidden(
                    f"<h1>403 Forbidden</h1>"
                    f"<p>Invalid certificate chain detected.</p>"
                    f"<p>Error: {verification_result['error']}</p>"
                    f"<p>Details: {verification_result.get('details', 'N/A')}</p>"
                )
            
            # Certificate is valid, allow access
            print("Certificate chain verified successfully")
            request.cert_verified = True
            request.cert_info = verification_result.get('cert_info', {})
            self._server_cert_verified = True
        return None
    
    def verify_certificate_chain(self):
        """
        Verify the complete 3-tier certificate chain on startup/request.
        Returns dict with 'valid' boolean and error details if invalid.
        """
        from django.conf import settings
        
        try:
            # Load all certificates
            with open(settings.PKI_SERVER_CERT, 'rb') as f:
                server_cert = load_pem_x509_certificate(f.read(), default_backend())
            
            with open(settings.PKI_INTERMEDIATE_CERT, 'rb') as f:
                intermediate_cert = load_pem_x509_certificate(f.read(), default_backend())
            
            with open(settings.PKI_ROOT_CERT, 'rb') as f:
                root_cert = load_pem_x509_certificate(f.read(), default_backend())
            
            # TIER 3: Verify server cert signed by Intermediate CA
            try:
                intermediate_cert.public_key().verify(
                    server_cert.signature,
                    server_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    server_cert.signature_hash_algorithm,
                )
                print("Tier 3: Server cert signed by Intermediate CA")
            except InvalidSignature:
                return {
                    'valid': False,
                    'error': 'Tier 3 verification failed',
                    'details': 'Server certificate NOT signed by Intermediate CA'
                }
            
            # TIER 2: Verify intermediate cert signed by Root CA
            try:
                root_cert.public_key().verify(
                    intermediate_cert.signature,
                    intermediate_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    intermediate_cert.signature_hash_algorithm,
                )
                print("Tier 2: Intermediate cert signed by Root CA")
            except InvalidSignature:
                return {
                    'valid': False,
                    'error': 'Tier 2 verification failed',
                    'details': 'Intermediate certificate NOT signed by Root CA'
                }
            
            # TIER 1: Verify Root CA is properly self-signed
            try:
                root_cert.public_key().verify(
                    root_cert.signature,
                    root_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    root_cert.signature_hash_algorithm,
                )
                print("Tier 1: Root CA properly self-signed")
            except InvalidSignature:
                return {
                    'valid': False,
                    'error': 'Tier 1 verification failed',
                    'details': 'Root CA signature invalid'
                }
            
            # Verify certificate expiration dates
            now = datetime.now()
            
            if not (server_cert.not_valid_before <= now <= server_cert.not_valid_after):
                return {
                    'valid': False,
                    'error': 'Server certificate expired or not yet valid',
                    'details': f'Valid from {server_cert.not_valid_before} to {server_cert.not_valid_after}'
                }
            
            if not (intermediate_cert.not_valid_before <= now <= intermediate_cert.not_valid_after):
                return {
                    'valid': False,
                    'error': 'Intermediate certificate expired or not yet valid',
                    'details': f'Valid from {intermediate_cert.not_valid_before} to {intermediate_cert.not_valid_after}'
                }
            
            if not (root_cert.not_valid_before <= now <= root_cert.not_valid_after):
                return {
                    'valid': False,
                    'error': 'Root certificate expired or not yet valid',
                    'details': f'Valid from {root_cert.not_valid_before} to {root_cert.not_valid_after}'
                }
            
            # Extract certificate information
            cert_info = {
                'server': {
                    'subject': server_cert.subject.rfc4514_string(),
                    'issuer': server_cert.issuer.rfc4514_string(),
                    'serial': server_cert.serial_number,
                    'valid_from': server_cert.not_valid_before,
                    'valid_until': server_cert.not_valid_after,
                },
                'intermediate': {
                    'subject': intermediate_cert.subject.rfc4514_string(),
                    'issuer': intermediate_cert.issuer.rfc4514_string(),
                    'serial': intermediate_cert.serial_number,
                },
                'root': {
                    'subject': root_cert.subject.rfc4514_string(),
                    'issuer': root_cert.issuer.rfc4514_string(),
                    'serial': root_cert.serial_number,
                }
            }
            
            print("Complete 3-tier certificate chain verified")
            return {
                'valid': True,
                'cert_info': cert_info
            }
            
        except FileNotFoundError as e:
            return {
                'valid': False,
                'error': 'Certificate file not found',
                'details': str(e)
            }
        except Exception as e:
            print("Certificate verification error")
            return {
                'valid': False,
                'error': 'Certificate verification error',
                'details': str(e)
            }
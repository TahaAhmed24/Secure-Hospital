from django.db import models
from django.contrib.auth.models import AbstractUser
import secrets
import base64
from django.contrib.auth.models import User

class UserKeyPair(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    
    # Encryption key (RSA-OAEP)
    enc_public_key = models.TextField()
    enc_encrypted_private_key = models.TextField()
    enc_salt = models.TextField()
    
    # Signing key (RSASSA-PKCS1-v1_5)
    sign_public_key = models.TextField()
    sign_encrypted_private_key = models.TextField()
    sign_salt = models.TextField()
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class UserDevice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices')

    # Device identification
    device_id = models.CharField(max_length=64, unique=True)  # Random unique ID for this device
    friendly_name = models.CharField(max_length=128)  # User-provided name like "My Laptop"

    # Device metadata
    user_agent = models.TextField()
    ip_address = models.GenericIPAddressField()

    # Device-encrypted keys (encrypted with device-specific symmetric key)
    device_encrypted_enc_private_key = models.TextField()
    device_encrypted_sign_private_key = models.TextField()

    # Timestamps
    last_used = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-last_used']

    def __str__(self):
        return f"{self.user.username} - {self.friendly_name}"
    
class MedicalFile(models.Model):
    """
    Represents a medical file's metadata (shared across all versions).
    This is the "base file" - each file can have multiple versions.
    """
    # Ownership
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='medical_files')

    # uploader info
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_files')
    created_at = models.DateTimeField(auto_now_add=True)

    # File type (same across all versions)
    mime_type = models.CharField(max_length=128, default='text/plain')

    deletion_requested_at = models.DateTimeField(null=True, blank=True)
    deletion_requested_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='file_deletion_requests'
    )

    def __str__(self):
        return f"File {self.id} - Patient: {self.patient.username} ({self.mime_type})"

    def get_latest_version(self):
        """Get the latest approved version"""
        return self.versions.filter(status='approved').order_by('-version_number').first()

    def verify_signature_chain(self):
        """
        Verify the signature chain for all versions of this file.
        Returns a dict with verification results.
        """
        from Crypto.PublicKey import RSA
        from Crypto.Signature import pkcs1_15
        from Crypto.Hash import SHA256
        import base64

        results = {
            'valid': True,
            'versions': {},
            'broken_at': None,
            'error': None
        }

        try:
            # Get all versions ordered by version_number
            versions = self.versions.all().order_by('version_number')

            if not versions.exists():
                results['error'] = 'No versions found'
                results['valid'] = False
                return results

            for version in versions:
                version_result = {
                    'valid': False,
                    'error': None,
                    'version_number': version.version_number
                }

                try:
                    # Get the creator's public signing key
                    try:
                        user_keypair = UserKeyPair.objects.get(user=version.created_by)
                        public_key_pem = user_keypair.sign_public_key
                        public_key = RSA.import_key(public_key_pem)
                    except UserKeyPair.DoesNotExist:
                        version_result['error'] = 'Creator public key not found'
                        results['versions'][version.id] = version_result
                        results['valid'] = False
                        results['broken_at'] = version.version_number
                        return results

                    # Prepare the data that was signed
                    if version.version_number == 1:
                        # Version 1: signature is of encrypted_content only
                        data_to_verify = bytes(version.encrypted_content)
                    else:
                        # Version 2+: signature is of (encrypted_content + previous_signature)
                        if not version.previous_version:
                            version_result['error'] = 'Missing previous version link'
                            results['versions'][version.id] = version_result
                            results['valid'] = False
                            results['broken_at'] = version.version_number
                            return results

                        data_to_verify = bytes(version.encrypted_content) + bytes(version.previous_version.signature)

                    # Hash the data
                    h = SHA256.new(data_to_verify)

                    # Verify the signature
                    try:
                        pkcs1_15.new(public_key).verify(h, bytes(version.signature))
                        version_result['valid'] = True
                    except (ValueError, TypeError) as e:
                        version_result['error'] = 'Invalid signature'
                        version_result['valid'] = False
                        results['valid'] = False
                        results['broken_at'] = version.version_number

                except Exception as e:
                    version_result['error'] = str(e)
                    results['valid'] = False
                    results['broken_at'] = version.version_number

                results['versions'][version.id] = version_result

                # Stop if we found an invalid signature
                if not version_result['valid']:
                    break

        except Exception as e:
            results['error'] = str(e)
            results['valid'] = False

        return results

class MedicalFileVersion(models.Model):
    """
    Represents a specific version of a medical file.
    Each version has its own encryption key (forward secrecy).
    Signatures are chained (blockchain-like) for tamper detection.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    # Reference to base file
    file = models.ForeignKey(MedicalFile, on_delete=models.CASCADE, related_name='versions')

    # Version chain
    version_number = models.PositiveIntegerField()
    previous_version = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='next_versions'
    )

    # Encrypted content (each version has unique encryption key)
    encrypted_content = models.BinaryField()
    size = models.PositiveIntegerField()

    # Chained signature: sign(encrypted_content + previous_version.signature)
    signature = models.BinaryField()

    # Version metadata
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='edited_versions')
    created_at = models.DateTimeField(auto_now_add=True)

    # Approval status
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')

    class Meta:
        unique_together = [['file', 'version_number']]
        ordering = ['-version_number']
        indexes = [
            models.Index(fields=['file', '-version_number']),
            models.Index(fields=['file', 'status']),
        ]

    def __str__(self):
        return f"File {self.file.id} - v{self.version_number} ({self.status})"

    def is_latest_approved(self):
        """Check if this is the latest approved version"""
        latest = self.file.get_latest_version()
        return latest and latest.id == self.id

class MedicalFileVersionAccess(models.Model):
    """
    Grants a user access to a specific version of a file.
    Each version has its own encryption key (forward secrecy).
    The symmetric key is encrypted with the user's public key.
    """
    # Reference to specific version
    version = models.ForeignKey(MedicalFileVersion, on_delete=models.CASCADE, related_name='access_grants')

    # User with access
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='version_access')

    # Encrypted data for this user
    encrypted_symmetric_key = models.TextField()  # Encrypted with user's public key
    encrypted_filename = models.TextField()  # User's encrypted copy of filename

    # Metadata
    granted_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='granted_version_access'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [['version', 'user']]
        indexes = [
            models.Index(fields=['user', 'version']),
        ]

    def __str__(self):
        return f"Access: {self.user.username} → File {self.version.file.id} v{self.version.version_number}"

class AuditLog(models.Model):
    """
    Audit log for all file operations.
    Records actions on specific versions.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    version = models.ForeignKey(
        MedicalFileVersion,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='audit_logs'
    )
    action = models.CharField(max_length=64)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['user', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.timestamp}"

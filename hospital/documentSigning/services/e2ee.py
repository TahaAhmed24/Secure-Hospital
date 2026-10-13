"""
E2EE Service - End-to-End Encryption Management

Handles all encryption infrastructure operations including:
- User key pair management (encryption and signing keys)
- Device registration and management
- Key retrieval and validation
"""

import secrets
from typing import Dict, List, Tuple, Any
from django.contrib.auth.models import User

from ..models import UserKeyPair, UserDevice


class E2EEService:
    """
    Service for managing End-to-End Encryption (E2EE) infrastructure.

    Responsibilities:
    - User key pair creation and retrieval
    - Public key access for file sharing
    - Device registration and management
    - Device key retrieval
    """

    @staticmethod
    def checkStatus(user: User) -> Dict[str, Any]:
        """
        Check if user has E2EE keys and device setup.

        Args:
            user: The Django user object

        Returns:
            Dict containing:
                - setup_complete (bool): Whether E2EE is fully configured
                - has_keys (bool): Whether user has encryption keys
                - has_device (bool): Device check status (client-side)
                - next_step (str|None): URL for next setup step if incomplete
        """
        has_keys = UserKeyPair.objects.filter(user=user).exists()

        if not has_keys:
            return {
                'setup_complete': False,
                'has_keys': False,
                'has_device': False,
                'next_step': '/setup/keys/'
            }

        # Keys exist, device presence is checked client-side via IndexedDB
        return {
            'setup_complete': True,
            'has_keys': True,
            'next_step': None
        }

    @staticmethod
    def createKeys(
        user: User,
        enc_public_key: str,
        enc_encrypted_private_key: str,
        enc_salt: str,
        sign_public_key: str,
        sign_encrypted_private_key: str,
        sign_salt: str
    ) -> UserKeyPair:
        """
        Create encryption and signing key pairs for a user.

        Args:
            user: The Django user object
            enc_public_key: Base64-encoded encryption public key
            enc_encrypted_private_key: Encrypted encryption private key
            enc_salt: Salt used for key derivation
            sign_public_key: Base64-encoded signing public key
            sign_encrypted_private_key: Encrypted signing private key
            sign_salt: Salt used for key derivation

        Returns:
            UserKeyPair: The created key pair object

        Raises:
            ValueError: If keys already exist for this user
        """
        if UserKeyPair.objects.filter(user=user).exists():
            raise ValueError('Keys already exist for this user')

        keypair = UserKeyPair.objects.create(
            user=user,
            enc_public_key=enc_public_key,
            enc_encrypted_private_key=enc_encrypted_private_key,
            enc_salt=enc_salt,
            sign_public_key=sign_public_key,
            sign_encrypted_private_key=sign_encrypted_private_key,
            sign_salt=sign_salt
        )

        return keypair

    @staticmethod
    def getKeys(user: User) -> UserKeyPair:
        """
        Retrieve all keys for a user.

        Args:
            user: The Django user object

        Returns:
            UserKeyPair: The user's key pair

        Raises:
            UserKeyPair.DoesNotExist: If user has no keys
        """
        return UserKeyPair.objects.get(user=user)

    @staticmethod
    def getPublicKey(user_id: int) -> str:
        """
        Get a user's public encryption key (for sharing files).

        Args:
            user_id: The user ID

        Returns:
            str: Base64-encoded public encryption key

        Raises:
            UserKeyPair.DoesNotExist: If user has no keys
        """
        keypair = UserKeyPair.objects.get(user_id=user_id)
        return keypair.enc_public_key

    @staticmethod
    def registerDevice(
        user: User,
        friendly_name: str,
        user_agent: str,
        ip_address: str,
        device_encrypted_enc_private_key: str,
        device_encrypted_sign_private_key: str
    ) -> Tuple[UserDevice, str]:
        """
        Register a new device for E2EE.

        Args:
            user: The Django user object
            friendly_name: User-provided device name (e.g., "My Laptop")
            user_agent: Browser user agent string
            ip_address: Client IP address
            device_encrypted_enc_private_key: Encryption private key encrypted with device key
            device_encrypted_sign_private_key: Signing private key encrypted with device key

        Returns:
            Tuple[UserDevice, str]: (device object, device_id)

        Raises:
            ValueError: If user has no keys setup yet
        """
        # Verify user has keys setup
        if not UserKeyPair.objects.filter(user=user).exists():
            raise ValueError('Keys not setup yet')

        # Generate unique device ID
        device_id = secrets.token_urlsafe(32)

        # Create device record
        device = UserDevice.objects.create(
            user=user,
            device_id=device_id,
            friendly_name=friendly_name,
            user_agent=user_agent,
            ip_address=ip_address,
            device_encrypted_enc_private_key=device_encrypted_enc_private_key,
            device_encrypted_sign_private_key=device_encrypted_sign_private_key
        )

        return device, device_id

    @staticmethod
    def getDeviceKeys(user: User, device_id: str) -> Dict[str, str]:
        """
        Get device-encrypted keys for the current device.
        Updates last_used timestamp.

        Args:
            user: The Django user object
            device_id: The device ID

        Returns:
            Dict containing device-encrypted keys

        Raises:
            UserDevice.DoesNotExist: If device not found
        """
        device = UserDevice.objects.get(user=user, device_id=device_id)

        # Update last_used timestamp (auto_now=True)
        device.save()

        return {
            'device_encrypted_enc_private_key': device.device_encrypted_enc_private_key,
            'device_encrypted_sign_private_key': device.device_encrypted_sign_private_key
        }

    @staticmethod
    def listDevices(user: User) -> List[Dict[str, Any]]:
        """
        List all registered devices for a user.

        Args:
            user: The Django user object

        Returns:
            List of device info dictionaries
        """
        devices = UserDevice.objects.filter(user=user).values(
            'device_id',
            'friendly_name',
            'user_agent',
            'ip_address',
            'last_used',
            'created_at'
        )

        return list(devices)

    @staticmethod
    def revokeDevice(user: User, device_id: str) -> None:
        """
        Revoke (delete) a registered device.

        Args:
            user: The Django user object
            device_id: The device ID to revoke

        Raises:
            UserDevice.DoesNotExist: If device not found
        """
        device = UserDevice.objects.get(user=user, device_id=device_id)
        device.delete()

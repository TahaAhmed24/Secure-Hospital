"""
Medical File Access Services

Handles medical file operations, version management, and access control.
Organized into three service classes following single responsibility principle:

- FileService: File lifecycle (create, delete, list, metadata)
- VersionService: Version management (create, approve, reject, list)
- AccessService: Access control (share, revoke, verify)
"""

import base64
from typing import Dict, List, Optional, Tuple, Any
from django.contrib.auth.models import User
from django.db.models import Q
from django.utils import timezone

from ..models import (
    UserKeyPair,
    MedicalFile,
    MedicalFileVersion,
    MedicalFileVersionAccess,
    AuditLog
)
from ..api_utils import require_patient_user, require_doctor_user


# ============================================================================
# File Service - Medical File Operations
# ============================================================================

class FileService:
    """
    Service for managing medical files and their content.

    Responsibilities:
    - File creation and upload
    - File listing and retrieval
    - File deletion and deletion requests
    - File metadata management
    """

    @staticmethod
    def insert(
        patient: User,
        uploader: User,
        mime_type: str,
        encrypted_content: bytes,
        signature: bytes,
        access_grants: List[Dict[str, Any]],
        status: str = 'approved'
    ) -> Tuple[MedicalFile, MedicalFileVersion]:
        """
        Create a new medical file with version 1.

        Creates:
        1. MedicalFile (metadata container)
        2. MedicalFileVersion (version 1 with content)
        3. MedicalFileVersionAccess entries (for each user)

        Args:
            patient: The patient who owns the file
            uploader: The user who uploaded the file
            mime_type: MIME type of the file
            encrypted_content: Encrypted file content (bytes)
            signature: Digital signature of the content
            access_grants: List of dicts with keys: user_id, encrypted_key, encrypted_filename
            status: Initial status ('approved' or 'pending')

        Returns:
            Tuple[MedicalFile, MedicalFileVersion]: Created file and version
        """
        # Step 1: Create MedicalFile (metadata only)
        medical_file = MedicalFile.objects.create(
            patient=patient,
            created_by=uploader,
            mime_type=mime_type
        )

        # Step 2: Create Version 1 with content
        version_1 = VersionService.submitNew(
            creator=uploader,
            file=medical_file,
            encrypted_content=encrypted_content,
            signature=signature,
            status=status
        )

        # Step 3: Grant access to users (always granted by patient - the data owner)
        AccessService.grantToVersion(
            version=version_1,
            access_grants=access_grants,
            granted_by=patient
        )

        return medical_file, version_1

    @staticmethod
    def delete(initiator: User, file_id: int) -> None:
        """
        Delete entire file with all versions.

        Only patients can delete their own files.
        Cascades to all versions and access grants.

        Args:
            initiator: The user deleting (must be patient who owns file)
            file_id: The file ID

        Raises:
            MedicalFile.DoesNotExist: If file not found or not owned
            PermissionError: If initiator is not the patient owner
        """
        require_patient_user(initiator)

        medical_file = MedicalFile.objects.get(
            id=file_id,
            patient=initiator
        )

        # Delete cascades to all versions and access grants
        medical_file.delete()

    @staticmethod
    def requestDeletion(doctor: User, file_id: int) -> MedicalFile:
        """
        Doctor requests to delete a file from patient's records.

        Args:
            doctor: The doctor requesting deletion
            file_id: The file ID

        Returns:
            MedicalFile: Updated file with deletion request

        Raises:
            MedicalFile.DoesNotExist: If file not found
            ValueError: If deletion already requested or no access
            PermissionError: If user is not a doctor
        """
        require_doctor_user(doctor)

        medical_file = MedicalFile.objects.get(id=file_id)

        # Verify doctor has access to latest version
        latest_version = medical_file.get_latest_version()
        if not latest_version:
            raise ValueError('No approved versions found')

        MedicalFileVersionAccess.objects.get(
            version=latest_version,
            user=doctor
        )

        # Check if already requested
        if medical_file.deletion_requested_by:
            raise ValueError('Deletion already requested')

        # Set deletion request
        medical_file.deletion_requested_by = doctor
        medical_file.deletion_requested_at = timezone.now()
        medical_file.save()

        return medical_file

    @staticmethod
    def approveDeletion(patient: User, file_id: int) -> None:
        """
        Patient approves deletion request and deletes file.

        Args:
            patient: The patient (must own the file)
            file_id: The file ID

        Raises:
            MedicalFile.DoesNotExist: If file not found or no deletion request
            PermissionError: If user is not the patient owner
        """
        require_patient_user(patient)

        medical_file = MedicalFile.objects.get(
            id=file_id,
            patient=patient,
            deletion_requested_by__isnull=False
        )

        medical_file.delete()

    @staticmethod
    def rejectDeletion(patient: User, file_id: int) -> MedicalFile:
        """
        Patient rejects deletion request.

        Args:
            patient: The patient (must own the file)
            file_id: The file ID

        Returns:
            MedicalFile: Updated file with deletion request cleared

        Raises:
            MedicalFile.DoesNotExist: If file not found or no deletion request
            PermissionError: If user is not the patient owner
        """
        require_patient_user(patient)

        medical_file = MedicalFile.objects.get(
            id=file_id,
            patient=patient,
            deletion_requested_by__isnull=False
        )

        medical_file.deletion_requested_by = None
        medical_file.deletion_requested_at = None
        medical_file.save()

        return medical_file

    @staticmethod
    def getMetadata(user: User, file_id: int) -> Dict[str, Any]:
        """
        Get file metadata including signature of latest approved version.

        Args:
            user: The requesting user
            file_id: The file ID

        Returns:
            Dict containing signature, uploader info, and version metadata

        Raises:
            MedicalFile.DoesNotExist: If file not found
            MedicalFileVersionAccess.DoesNotExist: If user has no access
        """
        from ..api_utils import verify_file_access

        medical_file, latest_version, grant = verify_file_access(user, file_id)

        # Get the version creator's signing key
        uploader_key = UserKeyPair.objects.get(user=latest_version.created_by)

        # Convert signature bytes to Base64
        signature_b64 = base64.b64encode(bytes(latest_version.signature)).decode('utf-8')

        return {
            'signature': signature_b64,
            'uploader_public_key': uploader_key.sign_public_key,
            'version_number': latest_version.version_number,
            'created_by': latest_version.created_by.username
        }

    @staticmethod
    def listForUser(user: User, patient_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        List files user has access to with encrypted metadata.

        Args:
            user: The requesting user
            patient_id: Optional patient ID filter (for doctors)

        Returns:
            List of file dictionaries with encrypted metadata
        """
        from database.models import Patient

        # Get all version access grants for this user
        access_grants = MedicalFileVersionAccess.objects.filter(
            user=user
        ).select_related('version__file', 'version__file__patient')

        # Optional filter by patient ID
        if patient_id:
            patient = Patient.objects.get(id=patient_id)
            access_grants = access_grants.filter(
                version__file__patient=patient.user
            )

        # Filter by role and status
        is_patient = hasattr(user, 'patient_profile')
        if not is_patient:
            # Doctors see approved + their own pending submissions
            access_grants = access_grants.filter(
                Q(version__status='approved') |
                Q(version__status='pending', version__created_by=user)
            )
        else:
            # Patients see approved and pending (not rejected)
            access_grants = access_grants.filter(
                version__status__in=['approved', 'pending']
            )

        # Group by file and get latest version
        files_dict = {}
        for grant in access_grants:
            file_id = grant.version.file.id
            version = grant.version

            if file_id in files_dict:
                if version.version_number > files_dict[file_id]['version'].version_number:
                    files_dict[file_id] = {'grant': grant, 'version': version}
            else:
                files_dict[file_id] = {'grant': grant, 'version': version}

        # Build response
        files = []
        for file_id, data in files_dict.items():
            grant = data['grant']
            version = data['version']
            medical_file = version.file

            files.append({
                'id': medical_file.id,
                'encrypted_filename': grant.encrypted_filename,
                'encrypted_symmetric_key': grant.encrypted_symmetric_key,
                'file_size': version.size,
                'version': version.version_number,
                'uploaded_by': medical_file.created_by.username,
                'granted_by': grant.granted_by.username if grant.granted_by else None,
                'status': version.status,
                'created_at': version.created_at.isoformat(),
                'deletion_requested': medical_file.deletion_requested_by is not None,
                'deletion_requested_by': medical_file.deletion_requested_by.username if medical_file.deletion_requested_by else None
            })

        return files

    @staticmethod
    def getContent(user: User, file_id: int) -> bytes:
        """
        Get encrypted file content (latest approved version).

        Args:
            user: The requesting user
            file_id: The file ID

        Returns:
            bytes: Encrypted file content

        Raises:
            MedicalFile.DoesNotExist: If file not found
            MedicalFileVersionAccess.DoesNotExist: If user has no access
        """
        from ..api_utils import verify_file_access

        medical_file, latest_version, grant = verify_file_access(user, file_id)
        return bytes(latest_version.encrypted_content)

    @staticmethod
    def getDetails(
        user: User,
        file_id: int,
        version_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive file details including all versions.

        Args:
            user: The requesting user
            file_id: The file ID
            version_id: Optional specific version ID

        Returns:
            Dict containing file, latest_version, grant, and versions list

        Raises:
            MedicalFile.DoesNotExist: If file not found
            MedicalFileVersionAccess.DoesNotExist: If user has no access
        """
        from ..api_utils import verify_file_access

        medical_file, latest_version, grant = verify_file_access(user, file_id, version_id)

        # Get all versions
        all_versions = MedicalFileVersion.objects.filter(
            file=medical_file
        ).order_by('-version_number')

        versions_data = [
            {
                'id': v.id,
                'version_number': v.version_number,
                'editor': v.created_by.username,
                'created_at': v.created_at.isoformat(),
                'status': v.status,
                'size': v.size
            }
            for v in all_versions
        ]

        return {
            'file': {
                'id': medical_file.id,
                'mime_type': medical_file.mime_type,
                'patient_id': medical_file.patient.id,
                'patient_username': medical_file.patient.username,
                'created_by': medical_file.created_by.username,
                'created_at': medical_file.created_at.isoformat(),
                'deletion_requested': medical_file.deletion_requested_by is not None,
                'deletion_requested_by': medical_file.deletion_requested_by.username if medical_file.deletion_requested_by else None,
            },
            'latest_version': {
                'id': latest_version.id,
                'version_number': latest_version.version_number,
                'encrypted_content': base64.b64encode(bytes(latest_version.encrypted_content)).decode('utf-8'),
                'signature': base64.b64encode(bytes(latest_version.signature)).decode('utf-8'),
                'size': latest_version.size,
                'status': latest_version.status,
                'created_by': latest_version.created_by.username,
                'created_at': latest_version.created_at.isoformat(),
            },
            'grant': {
                'encrypted_symmetric_key': grant.encrypted_symmetric_key,
                'encrypted_filename': grant.encrypted_filename,
                'granted_at': grant.created_at.isoformat(),
            },
            'versions': versions_data
        }


# ============================================================================
# Version Service - Version Management
# ============================================================================

class VersionService:
    """
    Service for managing file versions.

    Responsibilities:
    - Creating new versions (edits)
    - Version approval/rejection workflow
    - Version listing and retrieval
    - Signature chain verification
    """

    @staticmethod
    def submitNew(
        creator: User,
        file: MedicalFile,
        encrypted_content: bytes,
        signature: bytes,
        status: Optional[str] = None
    ) -> MedicalFileVersion:
        """
        Create a new version of file with computed version number and status.

        Args:
            creator: The user creating the version
            file: The MedicalFile object
            encrypted_content: Encrypted file content (bytes)
            signature: Digital signature (chained if version > 1)
            status: Optional explicit status (auto-computed if None)

        Returns:
            MedicalFileVersion: The created version
        """
        # Compute version number
        existing_versions = MedicalFileVersion.objects.filter(file=file)
        version_number = len(existing_versions) + 1

        # Auto-compute status if not provided
        if status is None:
            # Patient uploads are auto-approved, doctor uploads need approval
            status = "approved" if file.patient == creator else "pending"

        # Get previous version for chaining
        previous = file.get_latest_version() if version_number > 1 else None

        # Create new version
        new_version = MedicalFileVersion.objects.create(
            file=file,
            version_number=version_number,
            previous_version=previous,
            encrypted_content=encrypted_content,
            size=len(encrypted_content),
            signature=signature,
            created_by=creator,
            status=status
        )

        return new_version

    @staticmethod
    def deletePending(patient: User, file_id: int, version_id: int) -> bool:
        """
        Reject/delete a pending version.

        If rejecting version 1, deletes entire file.
        Otherwise, deletes just the version.

        Args:
            patient: The patient (must own the file)
            file_id: The file ID
            version_id: The version ID to reject

        Returns:
            bool: True if entire file was deleted, False if just version

        Raises:
            MedicalFile.DoesNotExist: If file not found
            MedicalFileVersion.DoesNotExist: If version not found
            PermissionError: If user is not the patient owner
        """
        require_patient_user(patient)

        medical_file = MedicalFile.objects.get(id=file_id, patient=patient)

        version = MedicalFileVersion.objects.get(
            id=version_id,
            file=medical_file,
            status='pending'
        )

        # If rejecting version 1, delete entire file
        if version.version_number == 1:
            medical_file.delete()
            return True

        # Otherwise, delete just this version
        version.delete()
        return False

    @staticmethod
    def approve(patient: User, file_id: int, version_id: int) -> MedicalFileVersion:
        """
        Approve a pending version.

        Auto-deletes sibling pending versions (same parent).

        Args:
            patient: The patient (must own the file)
            file_id: The file ID
            version_id: The version ID to approve

        Returns:
            MedicalFileVersion: The approved version

        Raises:
            MedicalFile.DoesNotExist: If file not found
            MedicalFileVersion.DoesNotExist: If version not found
            PermissionError: If user is not the patient owner
        """
        require_patient_user(patient)

        medical_file = MedicalFile.objects.get(id=file_id, patient=patient)

        version = MedicalFileVersion.objects.get(
            id=version_id,
            file=medical_file,
            status='pending'
        )

        # Approve this version
        version.status = 'approved'
        version.save()

        # Auto-delete sibling pending versions
        parent_version = version.previous_version
        if parent_version:
            MedicalFileVersion.objects.filter(
                file=medical_file,
                previous_version=parent_version,
                status='pending'
            ).exclude(id=version_id).delete()

        return version

    @staticmethod
    def listAll(user: User, file_id: int) -> Dict[str, Any]:
        """
        List all versions of a file with metadata.

        Args:
            user: The requesting user
            file_id: The file ID

        Returns:
            Dict with file_id, versions list, and total_versions

        Raises:
            MedicalFile.DoesNotExist: If file not found
            PermissionError: If user has no access
        """
        medical_file = MedicalFile.objects.get(id=file_id)

        # Verify user has access to at least one version
        user_has_access = MedicalFileVersionAccess.objects.filter(
            version__file=medical_file,
            user=user
        ).exists()

        if not user_has_access:
            raise PermissionError('Access denied')

        # Get all versions
        versions = MedicalFileVersion.objects.filter(
            file=medical_file
        ).order_by('version_number')

        version_list = []
        for version in versions:
            # Get access grant for this user (if exists)
            try:
                grant = MedicalFileVersionAccess.objects.get(
                    version=version,
                    user=user
                )
                has_access = True
                grant_data = {
                    'encrypted_symmetric_key': grant.encrypted_symmetric_key,
                    'encrypted_filename': grant.encrypted_filename
                }
            except MedicalFileVersionAccess.DoesNotExist:
                has_access = False
                grant_data = None

            version_list.append({
                'id': version.id,
                'version_number': version.version_number,
                'status': version.status,
                'created_by': version.created_by.username,
                'created_at': version.created_at.isoformat(),
                'size': version.size,
                'has_access': has_access,
                'grant': grant_data  # Include grant data for client-side re-encryption
            })

        return {
            'file_id': file_id,
            'versions': version_list,
            'total_versions': len(version_list)
        }

    @staticmethod
    def verifyChain(user: User, file_id: int) -> Dict[str, Any]:
        """
        Verify the signature chain for all versions of a file.

        Args:
            user: The requesting user
            file_id: The file ID

        Returns:
            Dict with verification results

        Raises:
            MedicalFile.DoesNotExist: If file not found
            PermissionError: If user has no access
        """
        medical_file = MedicalFile.objects.get(id=file_id)

        # Verify user has access
        user_has_access = MedicalFileVersionAccess.objects.filter(
            version__file=medical_file,
            user=user
        ).exists()

        if not user_has_access:
            raise PermissionError('Access denied')

        return medical_file.verify_signature_chain()


# ============================================================================
# Access Service - Access Control Management
# ============================================================================

class AccessService:
    """
    Service for managing file access control.

    Responsibilities:
    - Granting access to versions
    - Sharing files with additional users
    - Revoking access
    - Access listing and verification
    """

    @staticmethod
    def grantToVersion(
        version: MedicalFileVersion,
        access_grants: List[Dict[str, Any]],
        granted_by: User
    ) -> int:
        """
        Grant access to a specific version for multiple users.

        Args:
            version: The MedicalFileVersion object
            access_grants: List of dicts with: user_id, encrypted_key, encrypted_filename
            granted_by: The user granting access

        Returns:
            int: Number of access grants created
        """
        created_count = 0

        for grant in access_grants:
            user_id = grant['user_id']

            # Skip users without E2EE keys
            if not UserKeyPair.objects.filter(user_id=user_id).exists():
                continue

            _, created = MedicalFileVersionAccess.objects.get_or_create(
                version=version,
                user_id=user_id,
                defaults={
                    'encrypted_symmetric_key': grant['encrypted_key'],
                    'encrypted_filename': grant['encrypted_filename'],
                    'granted_by': granted_by
                }
            )

            if created:
                created_count += 1

        return created_count

    @staticmethod
    def shareVersion(
        user: User,
        file_id: int,
        version_id: int,
        access_grants: List[Dict[str, Any]]
    ) -> int:
        """
        Share access to a specific version with additional users.

        Args:
            user: The user sharing (must have access)
            file_id: The file ID
            version_id: The version ID
            access_grants: List of dicts with: user_id, encrypted_key, encrypted_filename

        Returns:
            int: Number of new users granted access

        Raises:
            MedicalFile.DoesNotExist: If file not found
            MedicalFileVersion.DoesNotExist: If version not found
            PermissionError: If user doesn't have access
        """
        medical_file = MedicalFile.objects.get(id=file_id)
        version = MedicalFileVersion.objects.get(id=version_id, file=medical_file)

        # Verify user has access
        MedicalFileVersionAccess.objects.get(version=version, user=user)

        # Access always granted by patient (data owner), not the sharer
        return AccessService.grantToVersion(version, access_grants, medical_file.patient)

    @staticmethod
    def shareAllVersions(
        user: User,
        file_id: int,
        access_grants: List[Dict[str, Any]]
    ) -> Tuple[int, int]:
        """
        Share access to ALL versions of a file.

        Args:
            user: The user sharing (must have access to latest)
            file_id: The file ID
            access_grants: List of dicts with:
                - user_id: int
                - version_grants: List[Dict] with version_id, encrypted_key, encrypted_filename

        Returns:
            Tuple[int, int]: (users_granted, total_grants)

        Raises:
            MedicalFile.DoesNotExist: If file not found
            ValueError: If no approved versions found
            PermissionError: If user doesn't have access
        """
        medical_file = MedicalFile.objects.get(id=file_id)
        latest_version = medical_file.get_latest_version()

        if not latest_version:
            raise ValueError('No approved versions found')

        # Verify user has access to latest
        MedicalFileVersionAccess.objects.get(version=latest_version, user=user)

        total_granted = 0
        users_granted = 0

        for user_grant in access_grants:
            user_id = user_grant["user_id"]
            version_grants = user_grant.get("version_grants", [])

            # Skip users without E2EE keys
            if not UserKeyPair.objects.filter(user_id=user_id).exists():
                continue

            user_version_count = 0
            for version_grant in version_grants:
                version_id = version_grant["version_id"]
                version = MedicalFileVersion.objects.get(id=version_id, file=medical_file)

                _, created = MedicalFileVersionAccess.objects.get_or_create(
                    user_id=user_id,
                    version=version,
                    defaults={
                        "encrypted_symmetric_key": version_grant["encrypted_key"],
                        "encrypted_filename": version_grant["encrypted_filename"],
                        "granted_by": medical_file.patient  # Always patient (data owner)
                    }
                )

                if created:
                    user_version_count += 1
                    total_granted += 1

            if user_version_count > 0:
                users_granted += 1

        return users_granted, total_granted

    @staticmethod
    def revokeUser(granter: User, user_id: int) -> int:
        """
        Revoke all access granted by a user to another user.

        Args:
            granter: The user who originally granted access
            user_id: The user whose access should be revoked

        Returns:
            int: Number of access grants revoked
        """
        deleted_count, _ = MedicalFileVersionAccess.objects.filter(
            granted_by=granter,
            user_id=user_id
        ).delete()

        return deleted_count

    @staticmethod
    def listForFile(file_id: int) -> List[int]:
        """
        Get list of user IDs with access to the latest approved version.

        Args:
            file_id: The file ID

        Returns:
            List[int]: User IDs with access

        Raises:
            MedicalFile.DoesNotExist: If file not found
            ValueError: If no approved versions found
        """
        medical_file = MedicalFile.objects.get(id=file_id)
        latest_version = medical_file.get_latest_version()

        if not latest_version:
            raise ValueError('No approved versions found')

        access = MedicalFileVersionAccess.objects.filter(
            version=latest_version
        ).values_list("user_id", flat=True)

        return list(access)

"""
Audit Service - Audit Logging

Handles all audit trail operations including:
- Creating audit log entries for file operations
- Querying audit history for files and users
- Compliance and security monitoring
"""

from typing import Dict, List, Optional, Any
from django.contrib.auth.models import User

from ..models import AuditLog, MedicalFile, MedicalFileVersion


class AuditService:
    """
    Service for managing audit logs.

    Responsibilities:
    - Creating audit log entries for file operations
    - Retrieving audit history for files
    - Retrieving audit history for users
    - Supporting compliance and security monitoring
    """

    @staticmethod
    def log(
        user: User,
        version: Optional[MedicalFileVersion],
        action: str,
        ip_address: Optional[str] = None
    ) -> AuditLog:
        """
        Create an audit log entry.

        Args:
            user: The user performing the action
            version: The file version (optional)
            action: Description of the action performed
            ip_address: Client IP address (optional)

        Returns:
            AuditLog: The created audit log entry

        Examples:
            Actions: 'upload', 'download', 'share', 'approve_version',
                    'reject_version', 'delete_file', 'request_deletion'
        """
        return AuditLog.objects.create(
            user=user,
            version=version,
            action=action,
            ip_address=ip_address
        )

    @staticmethod
    def getFileHistory(file_id: int, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit history for a specific file.

        Args:
            file_id: The file ID
            limit: Maximum number of entries to return (default: 100)

        Returns:
            List of audit log dictionaries ordered by timestamp (newest first)

        Raises:
            MedicalFile.DoesNotExist: If file not found
        """
        medical_file = MedicalFile.objects.get(id=file_id)

        logs = AuditLog.objects.filter(
            version__file=medical_file
        ).select_related('user', 'version').order_by('-timestamp')[:limit]

        return [
            {
                'user': log.user.username,
                'action': log.action,
                'version_number': log.version.version_number if log.version else None,
                'ip_address': log.ip_address,
                'timestamp': log.timestamp.isoformat()
            }
            for log in logs
        ]

    @staticmethod
    def getUserHistory(user: User, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit history for a specific user.

        Args:
            user: The user
            limit: Maximum number of entries to return (default: 100)

        Returns:
            List of audit log dictionaries ordered by timestamp (newest first)
        """
        logs = AuditLog.objects.filter(
            user=user
        ).select_related('version', 'version__file').order_by('-timestamp')[:limit]

        return [
            {
                'action': log.action,
                'file_id': log.version.file.id if log.version else None,
                'version_number': log.version.version_number if log.version else None,
                'ip_address': log.ip_address,
                'timestamp': log.timestamp.isoformat()
            }
            for log in logs
        ]

    @staticmethod
    def getRecentActivity(limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recent audit activity across all users and files.

        Useful for admin monitoring and security analysis.

        Args:
            limit: Maximum number of entries to return (default: 50)

        Returns:
            List of audit log dictionaries ordered by timestamp (newest first)
        """
        logs = AuditLog.objects.select_related(
            'user',
            'version',
            'version__file'
        ).order_by('-timestamp')[:limit]

        return [
            {
                'user': log.user.username,
                'action': log.action,
                'file_id': log.version.file.id if log.version else None,
                'version_number': log.version.version_number if log.version else None,
                'ip_address': log.ip_address,
                'timestamp': log.timestamp.isoformat()
            }
            for log in logs
        ]

    @staticmethod
    def getActionsByType(action: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit logs filtered by action type.

        Useful for analyzing specific types of operations (e.g., all downloads, all deletions).

        Args:
            action: The action type to filter (e.g., 'download', 'delete_file')
            limit: Maximum number of entries to return (default: 100)

        Returns:
            List of audit log dictionaries ordered by timestamp (newest first)
        """
        logs = AuditLog.objects.filter(
            action=action
        ).select_related('user', 'version', 'version__file').order_by('-timestamp')[:limit]

        return [
            {
                'user': log.user.username,
                'file_id': log.version.file.id if log.version else None,
                'version_number': log.version.version_number if log.version else None,
                'ip_address': log.ip_address,
                'timestamp': log.timestamp.isoformat()
            }
            for log in logs
        ]

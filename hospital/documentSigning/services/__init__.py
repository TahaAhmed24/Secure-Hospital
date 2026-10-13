"""
Services Package for Document Signing Application

This package implements the business logic layer following the MVP pattern.
Services are organized by domain responsibility.

Available Services:
- FileService: Medical file operations (create, delete, list)
- VersionService: Version management (create, approve, reject)
- AccessService: Access control (share, revoke, verify)
- E2EEService: Encryption infrastructure (keys, devices)
- AuditService: Audit logging
"""

from .medical_records import FileService, VersionService, AccessService
from .e2ee import E2EEService
from .audit import AuditService

__all__ = [
    'FileService',
    'VersionService',
    'AccessService',
    'E2EEService',
    'AuditService',
]

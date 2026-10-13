"""
Utility functions and decorators for API views
Reduces code duplication and standardizes error handling
"""
from functools import wraps
from typing import TYPE_CHECKING
from django.http import JsonResponse
from .models import MedicalFile, MedicalFileVersion, MedicalFileVersionAccess

if TYPE_CHECKING:
    from django.contrib.auth.models import User


def api_error_handler(func):
    """
    Decorator to handle common API errors and return standardized JSON responses
    """
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        try:
            return func(request, *args, **kwargs)
        except MedicalFile.DoesNotExist:
            return JsonResponse({'error': 'File not found'}, status=404)
        except MedicalFileVersion.DoesNotExist:
            return JsonResponse({'error': 'Version not found'}, status=404)
        except MedicalFileVersionAccess.DoesNotExist:
            return JsonResponse({'error': 'Access denied'}, status=403)
        except PermissionError as e:
            return JsonResponse({'error': str(e)}, status=403)
        except ValueError as e:
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return wrapper


def require_patient(func):
    """
    Decorator to ensure the user is a patient
    """
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        if not hasattr(request.user, 'patient_profile'):
            return JsonResponse({'error': 'Only patients can perform this action'}, status=403)
        return func(request, *args, **kwargs)
    return wrapper


def require_doctor(func):
    """
    Decorator to ensure the user is a doctor
    """
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        if not hasattr(request.user, 'doctor_profile'):
            return JsonResponse({'error': 'Only doctors can perform this action'}, status=403)
        return func(request, *args, **kwargs)
    return wrapper


def verify_file_access(user, file_id, version_id=None):
    """
    Verify that a user has access to a file or specific version

    Args:
        user: The Django user object
        file_id: The file ID
        version_id: Optional specific version ID

    Returns:
        tuple: (medical_file, version, access_grant)

    Raises:
        MedicalFile.DoesNotExist: If file doesn't exist
        MedicalFileVersion.DoesNotExist: If version doesn't exist
        MedicalFileVersionAccess.DoesNotExist: If user doesn't have access
    """
    from django.db.models import Q

    medical_file = MedicalFile.objects.get(id=file_id)

    is_patient = hasattr(user, 'patient_profile')

    if version_id:
        # Get specific version
        if is_patient:
            version = MedicalFileVersion.objects.get(
                id=version_id,
                file=medical_file,
                status__in=['approved', 'pending']
            )
        else:
            # Doctors can see approved OR their own pending submissions
            version = MedicalFileVersion.objects.filter(
                Q(id=version_id, file=medical_file, status='approved') |
                Q(id=version_id, file=medical_file, status='pending', created_by=user)
            ).first()

            if not version:
                raise MedicalFileVersion.DoesNotExist()
    else:
        # Get latest accessible version
        if is_patient:
            version = MedicalFileVersion.objects.filter(
                file=medical_file,
                status__in=['approved', 'pending']
            ).order_by('-version_number').first()
        else:
            version = medical_file.get_latest_version()

        if not version:
            raise MedicalFileVersion.DoesNotExist()

    # Verify access grant
    access_grant = MedicalFileVersionAccess.objects.get(
        version=version,
        user=user
    )

    return medical_file, version, access_grant


def get_user_role(user):
    """
    Get the user's role (patient, doctor, or unknown)

    Args:
        user: The Django user object

    Returns:
        str: 'patient', 'doctor', or 'unknown'
    """
    if hasattr(user, 'patient_profile'):
        return 'patient'
    elif hasattr(user, 'doctor_profile'):
        return 'doctor'
    else:
        return 'unknown'


def is_patient(user) -> bool:
    """
    Check if user is a patient.

    Args:
        user: The Django user object

    Returns:
        bool: True if user is a patient, False otherwise
    """
    return hasattr(user, 'patient_profile')


def is_doctor(user) -> bool:
    """
    Check if user is a doctor.

    Args:
        user: The Django user object

    Returns:
        bool: True if user is a doctor, False otherwise
    """
    return hasattr(user, 'doctor_profile')


def require_patient_user(user) -> None:
    """
    Raise PermissionError if user is not a patient.

    Use this in service methods for permission checking.
    For view functions, use the @require_patient decorator instead.

    Args:
        user: The Django user object

    Raises:
        PermissionError: If user is not a patient
    """
    if not is_patient(user):
        raise PermissionError('Only patients can perform this action')


def require_doctor_user(user) -> None:
    """
    Raise PermissionError if user is not a doctor.

    Use this in service methods for permission checking.
    For view functions, use the @require_doctor decorator instead.

    Args:
        user: The Django user object

    Raises:
        PermissionError: If user is not a doctor
    """
    if not is_doctor(user):
        raise PermissionError('Only doctors can perform this action')


def create_audit_log(user, version, action, ip_address=None):
    """
    Create an audit log entry

    Args:
        user: The Django user object
        version: The MedicalFileVersion object
        action: The action performed (string)
        ip_address: Optional IP address
    """
    from .models import AuditLog

    AuditLog.objects.create(
        user=user,
        version=version,
        action=action,
        ip_address=ip_address
    )

import json
import base64
import secrets
from django.db.models import Q
from database.models import Patient,Doctor
from django.contrib.auth.models import User
from authentication.models import WebAuthDevice
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404,render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from .models import UserKeyPair, MedicalFile, MedicalFileVersion, MedicalFileVersionAccess, AuditLog, UserDevice
from .api_utils import api_error_handler, require_patient, require_doctor, verify_file_access, get_user_role

# Import services
from .services import E2EEService, FileService, VersionService, AccessService, AuditService

class E2ESetupViews():
    @login_required
    @require_http_methods(["GET"])
    @api_error_handler
    def check_e2ee_status(request):
        """Check if user has E2EE keys and device setup"""
        status = E2EEService.checkStatus(request.user)
        return JsonResponse(status)

    @login_required
    @require_http_methods(["POST"])
    @api_error_handler
    def setup_keys(request):
        """Store both encryption and signing keys"""
        data = json.loads(request.body)

        E2EEService.createKeys(
            user=request.user,
            enc_public_key=data['enc_public_key'],
            enc_encrypted_private_key=data['enc_encrypted_private_key'],
            enc_salt=data['enc_salt'],
            sign_public_key=data['sign_public_key'],
            sign_encrypted_private_key=data['sign_encrypted_private_key'],
            sign_salt=data['sign_salt']
        )

        return JsonResponse({'success': True})

    @login_required
    @require_http_methods(["GET"])
    @api_error_handler
    def get_user_keys(request):
        """Get user's encryption and signing keys"""
        keypair = E2EEService.getKeys(request.user)

        return JsonResponse({
            'user_id': request.user.id,
            'enc_encrypted_private_key': keypair.enc_encrypted_private_key,
            'enc_salt': keypair.enc_salt,
            'enc_public_key': keypair.enc_public_key,
            'sign_encrypted_private_key': keypair.sign_encrypted_private_key,
            'sign_salt': keypair.sign_salt,
            'sign_public_key': keypair.sign_public_key
        })

    @login_required
    @require_http_methods(["GET"])
    @api_error_handler
    def get_public_key(request, user_id):
        """Get another user's public key for sharing files"""
        public_key = E2EEService.getPublicKey(user_id)
        return JsonResponse({'public_key': public_key})

    @login_required
    @require_http_methods(["POST"])
    @api_error_handler
    def setup_device(request):
        """Setup a new device for E2EE"""
        data = json.loads(request.body)

        # Get client IP (HTTP-specific logic stays in view)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0]
        else:
            ip_address = request.META.get('REMOTE_ADDR')

        # Register device via service
        device, device_id = E2EEService.registerDevice(
            user=request.user,
            friendly_name=data['friendly_name'],
            user_agent=data['user_agent'],
            ip_address=ip_address,
            device_encrypted_enc_private_key=data['device_encrypted_enc_private_key'],
            device_encrypted_sign_private_key=data['device_encrypted_sign_private_key']
        )

        return JsonResponse({
            'success': True,
            'device_id': device_id
        })

    @login_required
    @require_http_methods(["GET"])
    @api_error_handler
    def get_device_keys(request):
        """Get device-encrypted keys for current device"""
        device_id = request.GET.get('device_id')

        if not device_id:
            raise ValueError('device_id required')

        keys = E2EEService.getDeviceKeys(request.user, device_id)

        return JsonResponse(keys)

    @login_required
    @require_http_methods(["GET"])
    @api_error_handler
    def list_devices(request):
        """List all devices for current user"""
        devices = E2EEService.listDevices(request.user)
        return JsonResponse({'devices': devices})

    @login_required
    @require_http_methods(["POST"])
    @api_error_handler
    def revoke_device(request):
        """Revoke a device"""
        data = json.loads(request.body)
        device_id = data.get('device_id')

        if not device_id:
            raise ValueError('device_id required')

        E2EEService.revokeDevice(request.user, device_id)

        return JsonResponse({'success': True})


class MedicalRecordViews():
    @login_required
    @require_http_methods(["POST"])
    @api_error_handler
    def upload_file(request):
        """
        Create new medical file with version 1.
        Creates: MedicalFile (metadata) + MedicalFileVersion (content) + Access grants
        """
        from database.models import Patient

        # Parse request data
        encrypted_data = request.FILES.get('encrypted_file').read()
        metadata = json.loads(request.POST.get('metadata'))
        patient_id = request.POST.get('patient_id')
        access_grants = json.loads(request.POST.get('access_grants'))

        # Determine status and patient
        if patient_id:
            # Doctor uploading to a patient's record
            patient = Patient.objects.get(id=patient_id)
            upload_status = 'pending'
        elif hasattr(request.user, 'patient_profile'):
            # Patient uploading their own file
            patient = request.user.patient_profile
            upload_status = 'approved'
        else:
            raise ValueError('Invalid user type')

        # Create file via service
        medical_file, version_1 = FileService.insert(
            patient=patient.user,
            uploader=request.user,
            mime_type=metadata.get('mime_type', 'text/plain'),
            encrypted_content=encrypted_data,
            signature=base64.b64decode(metadata.get('signature')),
            access_grants=access_grants,
            status=upload_status
        )

        # Audit log
        AuditService.log(
            user=request.user,
            version=version_1,
            action='upload',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return JsonResponse({
            'success': True,
            'file_id': medical_file.id,
            'version_id': version_1.id,
            'version_number': 1,
            'status': upload_status
        })

    @login_required
    @require_http_methods(["GET"])
    @api_error_handler
    def file_metadata(request, file_id):
        """Get file metadata including signature of latest approved version"""
        metadata = FileService.getMetadata(request.user, file_id)
        return JsonResponse(metadata)
        
    @login_required
    @require_http_methods(["GET"])
    @api_error_handler
    def list_files(request):
        """List files user has access to (with encrypted metadata)"""
        patient_id = request.GET.get('patient_id')
        files = FileService.listForUser(request.user, patient_id)
        return JsonResponse({'files': files})

    @login_required
    @require_http_methods(["GET"])
    @api_error_handler
    def download_file(request, file_id):
        """Download encrypted file (latest approved version)"""
        # Get encrypted content
        encrypted_content = FileService.getContent(request.user, file_id)

        # Audit log
        # Need to get version for audit - use verify_file_access temporarily
        _, latest_version, _ = verify_file_access(request.user, file_id)
        AuditService.log(request.user, latest_version, 'download', request.META.get('REMOTE_ADDR'))

        # Return encrypted file content
        response = HttpResponse(
            encrypted_content,
            content_type='application/octet-stream'
        )
        response['Content-Disposition'] = f'attachment; filename="encrypted_{file_id}"'
        return response

    @login_required
    @require_http_methods(["POST"])
    @api_error_handler
    def share_file(request, file_id):
        """Share latest approved version with additional users (E2EE model: only store encrypted keys)"""
        payload = json.loads(request.body)
        access_grants = payload.get("access_grants", [])

        # Get latest version ID (for shareVersion service call)
        medical_file, latest_version, _ = verify_file_access(request.user, file_id)

        # Share via service
        AccessService.shareVersion(
            user=request.user,
            file_id=file_id,
            version_id=latest_version.id,
            access_grants=access_grants
        )

        return JsonResponse({"status": "ok"})

    @login_required
    @require_http_methods(["POST"])
    @api_error_handler
    def share_access_to_version(request, file_id, version_id):
        """
        Share access to a specific file version with additional users.
        This is a reusable endpoint for granting access to any version.
        """
        payload = json.loads(request.body)
        access_grants = payload.get("access_grants", [])

        # Share via service
        granted_count = AccessService.shareVersion(
            user=request.user,
            file_id=file_id,
            version_id=version_id,
            access_grants=access_grants
        )

        # Audit log
        version = MedicalFileVersion.objects.get(id=version_id)
        AuditService.log(
            user=request.user,
            version=version,
            action=f'share_version_access_{granted_count}_users',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return JsonResponse({
            "success": True,
            "granted_count": granted_count,
            "message": f"Access granted to {granted_count} new user(s) for version {version.version_number}"
        })

    @login_required
    @require_http_methods(["POST"])
    @api_error_handler
    def share_access_to_all_versions(request, file_id):
        """
        Share access to ALL versions of a file with specified users.
        Useful when adding a new doctor to a patient - they get access to entire file history.

        Payload:
        {
            "access_grants": [
                {
                    "user_id": 123,
                    "version_grants": [
                        {
                            "version_id": 456,
                            "encrypted_key": "base64...",
                            "encrypted_filename": "base64..."
                        },
                        ...
                    ]
                },
                ...
            ]
        }
        """
        payload = json.loads(request.body)
        access_grants = payload.get("access_grants", [])

        # Share all versions via service
        users_granted, total_granted = AccessService.shareAllVersions(
            user=request.user,
            file_id=file_id,
            access_grants=access_grants
        )

        # Audit log
        medical_file = MedicalFile.objects.get(id=file_id)
        latest_version = medical_file.get_latest_version()
        AuditService.log(
            user=request.user,
            version=latest_version,
            action=f'share_all_versions_{users_granted}_users_{total_granted}_grants',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return JsonResponse({
            "success": True,
            "users_granted": users_granted,
            "total_grants": total_granted,
            "message": f"Access granted to {users_granted} user(s) across {total_granted} version(s)"
        })

    @login_required
    @require_http_methods(["POST"])
    @api_error_handler
    def revoke_access_to_records(request, user_id):
        """Revoke all access granted by current user to specified user"""
        revoked_count = AccessService.revokeUser(request.user, user_id)
        return JsonResponse({
            'success': True,
            'revoked_count': revoked_count,
            'message': f'Successfully revoked {revoked_count} access grant(s)'
        })
        
    @login_required
    @require_http_methods(["POST"])
    @require_patient
    @api_error_handler
    def approve_file(request, file_id):
        """Approve a pending version (patient only) - auto-deletes sibling pending versions"""
        # Parse request
        data = json.loads(request.body)
        version_id = data.get('version_id')

        if not version_id:
            raise ValueError('version_id required')

        # Approve via service
        version = VersionService.approve(
            patient=request.user,
            file_id=file_id,
            version_id=version_id
        )

        # Audit log
        AuditService.log(
            user=request.user,
            version=version,
            action='approve_version',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return JsonResponse({
            'success': True,
            'message': 'Version approved, sibling versions auto-deleted'
        })

    @login_required
    @require_http_methods(["POST"])
    @require_patient
    @api_error_handler
    def reject_file(request, file_id):
        """Reject a pending version (patient only) - deletes entire file if version 1, otherwise deletes the version"""
        # Parse request
        data = json.loads(request.body)
        version_id = data.get('version_id')

        if not version_id:
            raise ValueError('version_id required')

        # Get version for audit log before deletion
        version = MedicalFileVersion.objects.get(id=version_id)

        # Audit log before deletion
        AuditService.log(
            user=request.user,
            version=version,
            action='reject_version_delete',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        # Delete via service
        file_deleted = VersionService.deletePending(
            patient=request.user,
            file_id=file_id,
            version_id=version_id
        )

        if file_deleted:
            return JsonResponse({'success': True, 'message': 'Version 1 rejected. File deleted entirely.'})
        else:
            return JsonResponse({'success': True, 'message': 'Version rejected and deleted'})

    @login_required
    @require_http_methods(["POST"])
    @require_patient
    @api_error_handler
    def delete_file(request, file_id):
        """Delete entire file with all versions (patient only)"""
        # Get latest version for audit log before deletion
        medical_file = MedicalFile.objects.get(id=file_id)
        latest_version = medical_file.get_latest_version()

        # Audit log before deletion
        AuditService.log(
            user=request.user,
            version=latest_version,
            action='delete_file',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        # Delete via service
        FileService.delete(initiator=request.user, file_id=file_id)

        return JsonResponse({'success': True, 'message': 'File and all versions deleted successfully'})

    @login_required
    @require_http_methods(["POST"])
    @require_doctor
    @api_error_handler
    def request_deletion(request, file_id):
        """Doctor requests to delete a file from patient's records"""
        # Request deletion via service
        medical_file = FileService.requestDeletion(doctor=request.user, file_id=file_id)

        # Audit log
        latest_version = medical_file.get_latest_version()
        AuditService.log(
            user=request.user,
            version=latest_version,
            action='request_deletion',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return JsonResponse({'success': True, 'message': 'Deletion request submitted. Awaiting patient approval.'})

    @login_required
    @require_http_methods(["POST"])
    @require_patient
    @api_error_handler
    def reject_deletion(request, file_id):
        """Patient rejects deletion request"""
        # Reject deletion via service
        medical_file = FileService.rejectDeletion(patient=request.user, file_id=file_id)

        # Audit log
        latest_version = medical_file.get_latest_version()
        AuditService.log(
            user=request.user,
            version=latest_version,
            action='reject_deletion',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return JsonResponse({'success': True, 'message': 'Deletion request rejected.'})
        
    @login_required
    @require_http_methods(["POST"])
    @require_patient
    @api_error_handler
    def approve_deletion(request, file_id):
        """Patient approves deletion request and deletes entire file with all versions"""
        # Get latest version for audit log before deletion
        medical_file = MedicalFile.objects.get(id=file_id)
        latest_version = medical_file.get_latest_version()

        # Audit log before deletion
        AuditService.log(
            user=request.user,
            version=latest_version,
            action='approve_deletion',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        # Approve deletion via service (deletes the file)
        FileService.approveDeletion(patient=request.user, file_id=file_id)

        return JsonResponse({'success': True, 'message': 'Deletion approved. File and all versions deleted successfully.'})

    @login_required
    @api_error_handler
    def file_access_list(request, file_id):
        """Get list of users with access to the latest approved version"""
        user_ids = AccessService.listForFile(file_id)
        return JsonResponse({"users": user_ids})

    @login_required
    @require_http_methods(["GET"])
    @api_error_handler
    def list_file_versions(request, file_id):
        """
        List all versions of a file with their IDs and metadata.
        Useful for clients that need to share access to all versions.
        """
        result = VersionService.listAll(user=request.user, file_id=file_id)
        return JsonResponse(result)

    @login_required
    @require_http_methods(["GET"])
    @api_error_handler
    def get_file(request, file_id):
        """Get file metadata, specific or latest version, and version history"""
        # Check if specific version is requested via query parameter
        version_id = request.GET.get('version')

        # Get file details via service
        response_data = FileService.getDetails(
            user=request.user,
            file_id=file_id,
            version_id=int(version_id) if version_id else None
        )

        # Audit log
        version = MedicalFileVersion.objects.get(id=response_data['latest_version']['id'])
        AuditService.log(
            user=request.user,
            version=version,
            action='get_file',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return JsonResponse(response_data)

    @login_required
    @require_http_methods(["GET"])
    @api_error_handler
    def verify_signature_chain(request, file_id):
        """Verify the signature chain for all versions of a file"""
        # Verify chain via service
        verification_results = VersionService.verifyChain(user=request.user, file_id=file_id)

        # Audit log
        medical_file = MedicalFile.objects.get(id=file_id)
        latest_version = medical_file.get_latest_version()
        AuditService.log(
            user=request.user,
            version=latest_version,
            action='verify_signature_chain',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return JsonResponse(verification_results)

    @login_required
    @require_http_methods(["POST"])
    @api_error_handler
    def create_new_version(request):
        """Create a new version of an existing file (edit with new encryption key)"""
        # Parse request data
        encrypted_data = request.FILES.get('encrypted_file').read()
        file_id = request.POST.get('file_id')
        metadata = json.loads(request.POST.get('metadata'))
        access_grants = json.loads(request.POST.get('access_grants'))

        # Get the medical file and verify access
        medical_file = MedicalFile.objects.get(id=file_id)
        parent_version = medical_file.get_latest_version()

        if not parent_version:
            raise ValueError('No approved version to edit')

        # Verify user has access to parent version
        MedicalFileVersionAccess.objects.get(
            version=parent_version,
            user=request.user
        )

        # Decode signature from metadata
        signature = base64.b64decode(metadata.get('signature'))

        # Create new version via service
        new_version = VersionService.submitNew(
            creator=request.user,
            file=medical_file,
            encrypted_content=encrypted_data,
            signature=signature
        )

        # Grant access via service (always granted by patient - the data owner)
        AccessService.grantToVersion(
            version=new_version,
            access_grants=access_grants,
            granted_by=medical_file.patient
        )

        # Audit log
        AuditService.log(
            user=request.user,
            version=new_version,
            action='create_version',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return JsonResponse({
            'success': True,
            'message': 'Version created successfully',
            'file_id': medical_file.id,
            'version_id': new_version.id,
            'version_number': new_version.version_number,
            'status': new_version.status
        })

@login_required
def upload_page(request):
    return render(request, 'upload.html')

@login_required
@require_http_methods(["GET"])
def list_users(request):
    """
    List shareable users depending on role:

    - If the user is a PATIENT → return their appointed doctors.
    - If the user is a DOCTOR → return their assigned patients.
    - If patient_id is provided → return the patient + all their appointed doctors (for doctor uploading to patient record).
    """

    # Special case: if patient_id is provided, return patient + their doctors
    patient_id = request.GET.get('patient_id')
    if patient_id:
        try:
            from database.models import Patient
            patient = Patient.objects.get(id=patient_id)

            # Build list: patient + all their appointed doctors
            users = []

            # Add the patient themselves
            users.append({
                "id": patient.user.id,
                "username": patient.user.username,
                "first_name": patient.first_name,
                "last_name": patient.last_name
            })

            # Add all appointed doctors
            for doctor in patient.appointed_doctors.all():
                users.append({
                    "id": doctor.user.id,
                    "username": doctor.user.username,
                    "first_name": doctor.first_name,
                    "last_name": doctor.last_name
                })

            return JsonResponse({"users": users})
        except Patient.DoesNotExist:
            return JsonResponse({"error": "Patient not found"}, status=404)

    role = request.session.get("role")
    print(role)
    if role == "patient":
        # Patient → list their appointed doctors
        try:
            patient = request.user.patient_profile
        except Patient.DoesNotExist:
            return JsonResponse({"users": []})

        doctors = patient.appointed_doctors.all().values(
            "user__id",
            "first_name",
            "last_name",
            "user__username"
        )

        # Normalize field names
        data = [
            {
                "id": d["user__id"],
                "username": d["user__username"],
                "first_name": d["first_name"],
                "last_name": d["last_name"]
            }
            for d in doctors
        ]

        return JsonResponse({"users": data})

    elif role == "doctor":
        # Doctor → list their assigned patients
        try:
            doctor = request.user.doctor_profile
        except Doctor.DoesNotExist:
            return JsonResponse({"users": []})

        patients = doctor.patients.all().values(
            "user__id",
            "first_name",
            "last_name",
            "user__username"
        )

        data = [
            {
                "id": p["user__id"],
                "username": p["user__username"],
                "first_name": p["first_name"],
                "last_name": p["last_name"]
            }
            for p in patients
        ]

        return JsonResponse({"users": data})

    else:
        # Unknown role → return empty
        return JsonResponse({"users": []})

from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
import json

from .models import Doctor, Patient, AppointmentRequest
from django.contrib.auth.models import User
from .models import Doctor, Patient

@login_required
@require_http_methods(["GET"])
def list_available_doctors(request):
    """
    For patients: List only truly available doctors for appointment.
    Excludes doctors who are already appointed or have pending requests.
    """
    try:
        # Verify user is a patient
        if not hasattr(request.user, 'patient_profile'):
            return JsonResponse({'error': 'Only patients can view this'}, status=403)

        patient = request.user.patient_profile

        # Get patient's current doctors
        appointed_doctor_ids = set(patient.appointed_doctors.values_list('id', flat=True))

        # Get doctors with any pending requests (from either side)
        doctors_with_pending_requests = set(
            AppointmentRequest.objects.filter(
                patient=patient,
                status='pending'
            ).values_list('doctor_id', flat=True)
        )

        # Get all doctors excluding appointed and those with pending requests
        available_doctors = Doctor.objects.exclude(
            id__in=appointed_doctor_ids | doctors_with_pending_requests
        ).select_related('user').values(
            'id',
            'first_name',
            'last_name',
            'medical_organisation',
            'user__username',
            'user__id'
        )

        doctors_list = []
        for doctor in available_doctors:
            doctor_data = {
                'id': doctor['id'],
                'userId': doctor['user__id'],
                'first_name': doctor['first_name'],
                'last_name': doctor['last_name'],
                'medical_organisation': doctor['medical_organisation'],
                'username': doctor['user__username']
            }
            doctors_list.append(doctor_data)

        return JsonResponse({'doctors': doctors_list})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@login_required
@require_http_methods(["GET"])
def list_available_patients(request):
    """
    For doctors: List only truly available patients to send appointment requests to.
    Excludes patients who are already current patients or have pending requests.
    """
    try:
        # Verify user is a doctor
        if not hasattr(request.user, 'doctor_profile'):
            return JsonResponse({'error': 'Only doctors can view this'}, status=403)

        doctor = request.user.doctor_profile

        # Get doctor's current patients
        current_patient_ids = set(doctor.patients.values_list('id', flat=True))

        # Get patients with pending requests
        patients_with_pending_requests = set(
            AppointmentRequest.objects.filter(
                doctor=doctor,
                status='pending'
            ).values_list('patient_id', flat=True)
        )

        # Get all patients excluding current and those with pending requests
        available_patients = Patient.objects.exclude(
            id__in=current_patient_ids | patients_with_pending_requests
        ).select_related('user').values(
            'id',
            'first_name',
            'last_name',
            'user__username'
        )

        patients_list = []
        for patient in available_patients:
            patient_data = {
                'id': patient['id'],
                'first_name': patient['first_name'],
                'last_name': patient['last_name'],
                'username': patient['user__username']
            }
            patients_list.append(patient_data)

        return JsonResponse({'patients': patients_list})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def send_appointment_request(request):
    """
    Doctor sends appointment request to a patient.
    Patient can also directly add a doctor (auto-approved).
    """
    try:
        data = json.loads(request.body)

        if hasattr(request.user, 'doctor_profile'):
            # Doctor sending request
            doctor = request.user.doctor_profile
            patient_id = data.get('patient_id')
            message = data.get('message', '')

            if not patient_id:
                return JsonResponse({'error': 'patient_id required'}, status=400)

            patient = Patient.objects.get(id=patient_id)

            # Check if already appointed
            if patient.appointed_doctors.filter(id=doctor.id).exists():
                return JsonResponse({'error': 'Already appointed to this patient'}, status=400)

            # Create or update request
            request_obj, created = AppointmentRequest.objects.get_or_create(
                doctor=doctor,
                patient=patient,
                defaults={'message': message, 'status': 'pending'}
            )

            if not created and request_obj.status == 'rejected':
                # If previously rejected, allow re-requesting
                request_obj.status = 'pending'
                request_obj.message = message
                request_obj.save()

            return JsonResponse({
                'success': True,
                'request_id': request_obj.id,
                'message': 'Request sent to patient'
            })

        elif hasattr(request.user, 'patient_profile'):
            # Patient directly adding a doctor (auto-approved)
            patient = request.user.patient_profile
            doctor_id = data.get('doctor_id')

            if not doctor_id:
                return JsonResponse({'error': 'doctor_id required'}, status=400)

            doctor = Doctor.objects.get(id=doctor_id)

            # Check if already appointed
            if patient.appointed_doctors.filter(id=doctor.id).exists():
                return JsonResponse({'error': 'Doctor already appointed'}, status=400)

            # Add directly (no approval needed)
            patient.appointed_doctors.add(doctor)

            return JsonResponse({
                'success': True,
                'message': 'Doctor appointed successfully'
            })

        else:
            return JsonResponse({'error': 'Invalid user type'}, status=403)

    except (Doctor.DoesNotExist, Patient.DoesNotExist):
        return JsonResponse({'error': 'Doctor or patient not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def respond_to_request(request):
    """
    Patient approves or rejects a doctor's appointment request.
    """
    try:
        # Verify user is a patient
        if not hasattr(request.user, 'patient_profile'):
            return JsonResponse({'error': 'Only patients can respond to requests'}, status=403)

        patient = request.user.patient_profile
        data = json.loads(request.body)

        request_id = data.get('request_id')
        action = data.get('action')  # 'approve' or 'reject'

        if not request_id or action not in ['approve', 'reject']:
            return JsonResponse({'error': 'request_id and action (approve/reject) required'}, status=400)

        appointment_request = AppointmentRequest.objects.get(
            id=request_id,
            patient=patient,
            status='pending'
        )

        if action == 'approve':
            appointment_request.status = 'approved'
            appointment_request.save()

            # Add doctor to patient's appointed doctors
            patient.appointed_doctors.add(appointment_request.doctor)

            return JsonResponse({
                'success': True,
                'message': 'Doctor appointed successfully'
            })
        else:
            appointment_request.status = 'rejected'
            appointment_request.save()

            return JsonResponse({
                'success': True,
                'message': 'Request rejected'
            })

    except AppointmentRequest.DoesNotExist:
        return JsonResponse({'error': 'Request not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def remove_doctor(request):
    """
    Patient removes an appointed doctor.
    """
    try:
        # Verify user is a patient
        if not hasattr(request.user, 'patient_profile'):
            return JsonResponse({'error': 'Only patients can remove doctors'}, status=403)

        patient = request.user.patient_profile
        data = json.loads(request.body)

        doctor_id = data.get('doctor_id')

        if not doctor_id:
            return JsonResponse({'error': 'doctor_id required'}, status=400)

        doctor = Doctor.objects.get(id=doctor_id)

        # Remove doctor from patient's appointed doctors
        patient.appointed_doctors.remove(doctor)

        # Delete any existing appointment requests to allow fresh requests in the future
        AppointmentRequest.objects.filter(
            doctor=doctor,
            patient=patient
        ).delete()

        return JsonResponse({
            'success': True,
            'message': 'Doctor removed successfully'
        })

    except Doctor.DoesNotExist:
        return JsonResponse({'error': 'Doctor not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@login_required
@require_http_methods(["GET"])
def my_doctors(request):
    """
    For patients: Get list of appointed doctors.
    """
    try:
        # Verify user is a patient
        if not hasattr(request.user, 'patient_profile'):
            return JsonResponse({'error': 'Only patients can view this'}, status=403)

        patient = request.user.patient_profile

        doctors = patient.appointed_doctors.all().values(
            'id',
            'first_name',
            'last_name',
            'medical_organisation',
            'user__username',
            'user__id'
        )

        return JsonResponse({'doctors': list(doctors)})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@login_required
@require_http_methods(["GET"])
def my_patients(request):
    """
    For doctors: Get list of current patients.
    """
    try:
        # Verify user is a doctor
        if not hasattr(request.user, 'doctor_profile'):
            return JsonResponse({'error': 'Only doctors can view this'}, status=403)

        doctor = request.user.doctor_profile

        patients = doctor.patients.all().values(
            'id',
            'first_name',
            'last_name',
            'user__username'
        )
        
        patients_list = []
        for patient in patients:
            patient_data = {
                'id': patient['id'],
                'first_name': patient['first_name'],
                'last_name': patient['last_name'],
                'username': patient['user__username']
            }
            patients_list.append(patient_data)

        return JsonResponse({'patients': list(patients_list)})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@login_required
@require_http_methods(["GET"])
def pending_appointment_requests(request):
    """
    For patients: Get list of doctors who have sent pending appointment requests.
    """
    try:
        # Verify user is a patient
        if not hasattr(request.user, 'patient_profile'):
            return JsonResponse({'error': 'Only patients can view this'}, status=403)

        patient = request.user.patient_profile

        # Get pending requests from doctors
        pending_requests = AppointmentRequest.objects.filter(
            patient=patient,
            status='pending',
            doctor__isnull=False
        ).select_related('doctor__user').values(
            'id',
            'doctor_id',
            'doctor__first_name',
            'doctor__last_name',
            'doctor__medical_organisation',
            'doctor__user__username',
            'message',
            'created_at'
        )

        doctors_list = []
        for req in pending_requests:
            doctor_data = {
                'id': req['doctor_id'],
                'first_name': req['doctor__first_name'],
                'last_name': req['doctor__last_name'],
                'medical_organisation': req['doctor__medical_organisation'],
                'username': req['doctor__user__username'],
                'request_id': req['id'],
                'message': req['message'],
                'created_at': req['created_at'].isoformat()
            }
            doctors_list.append(doctor_data)

        return JsonResponse({'doctors': doctors_list})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@login_required
@require_http_methods(["GET"])
def pending_patients_requests(request):
    """
    For doctors: Get list of patients the doctor has sent pending appointment requests to.
    """
    try:
        # Verify user is a doctor
        if not hasattr(request.user, 'doctor_profile'):
            return JsonResponse({'error': 'Only doctors can view this'}, status=403)

        doctor = request.user.doctor_profile

        # Get pending requests sent by this doctor
        pending_requests = AppointmentRequest.objects.filter(
            doctor=doctor,
            status='pending',
            patient__isnull=False
        ).select_related('patient__user').values(
            'id',
            'patient_id',
            'patient__first_name',
            'patient__last_name',
            'patient__user__username',
            'message',
            'created_at'
        )

        patients_list = []
        for req in pending_requests:
            patient_data = {
                'id': req['patient_id'],
                'first_name': req['patient__first_name'],
                'last_name': req['patient__last_name'],
                'username': req['patient__user__username'],
                'request_id': req['id'],
                'message': req['message'],
                'created_at': req['created_at'].isoformat()
            }
            patients_list.append(patient_data)

        return JsonResponse({'patients': patients_list})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@login_required
@require_http_methods(["GET"])
def get_profile(request):
    """
    Get user profile data.
    For patients: returns encrypted fields.
    For doctors: returns plaintext fields.
    """
    try:
        if hasattr(request.user, 'patient_profile'):
            patient = request.user.patient_profile
            return JsonResponse({
                'role': 'patient',
                'first_name': patient.first_name or '',
                'last_name': patient.last_name or '',
                'date_of_birth': patient.date_of_birth or ''
            })
        elif hasattr(request.user, 'doctor_profile'):
            doctor = request.user.doctor_profile
            return JsonResponse({
                'role': 'doctor',
                'first_name': doctor.first_name or '',
                'last_name': doctor.last_name or '',
                'medical_organisation': doctor.medical_organisation or ''
            })
        else:
            return JsonResponse({'error': 'No profile found'}, status=404)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def update_profile(request):
    """
    Update user profile data.
    For patients: accepts encrypted fields.
    For doctors: accepts plaintext fields.
    """
    try:
        data = json.loads(request.body)

        if hasattr(request.user, 'patient_profile'):
            patient = request.user.patient_profile

            # Update encrypted fields
            if 'first_name' in data:
                patient.first_name = data['first_name']
            if 'last_name' in data:
                patient.last_name = data['last_name']
            if 'date_of_birth' in data:
                patient.date_of_birth = data['date_of_birth']

            patient.save()

            return JsonResponse({
                'success': True,
                'message': 'Profile updated successfully'
            })

        elif hasattr(request.user, 'doctor_profile'):
            doctor = request.user.doctor_profile

            # Update plaintext fields
            if 'first_name' in data:
                doctor.first_name = data['first_name']
            if 'last_name' in data:
                doctor.last_name = data['last_name']
            if 'medical_organisation' in data:
                doctor.medical_organisation = data['medical_organisation']

            doctor.save()

            return JsonResponse({
                'success': True,
                'message': 'Profile updated successfully'
            })
        else:
            return JsonResponse({'error': 'No profile found'}, status=404)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

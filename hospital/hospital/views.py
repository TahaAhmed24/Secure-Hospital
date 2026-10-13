from django.contrib.auth import get_user_model, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView
from django.forms import modelform_factory
from django.shortcuts import redirect, render
from django.views.generic import UpdateView
from django.views.generic.edit import CreateView
from database.models import Doctor, Patient
from django.views.generic import TemplateView

from .forms import (
    DoctorForm,
    PatientForm,
    StyledAuthenticationForm,
    StyledModelForm,
    StyledUserCreationForm,
    UsernameOnlyAuthenticationForm,
)

def home(request):
    return render(request, "home.html")


@login_required
def private(request):
    for key, value in request.session.items():
        print(f"{key}: {value}")
    return render(request, "private.html")

class ProfileView(LoginRequiredMixin, UpdateView):
    template_name = "profile.html"
    success_url = "/profile/"

    def get_object(self, queryset=None):
        role = self.request.session.get("role")
        if role == "doctor":
            return self.request.user.doctor_profile
        elif role == "patient":
            return self.request.user.patient_profile
        return self.request.user

    def get_form_class(self):
        role = self.request.session.get("role")
        if role == "doctor":
            return DoctorForm
        elif role == "patient":
            return PatientForm

    def form_valid(self, form):
        # Save the related profile object
        obj = form.save()

        # Optionally update User fields (like email) if this is a profile
        user = self.request.user
        if hasattr(obj, 'user'):
            if self.request.session['role'] == 'doctor':
                user.medical_organisation = obj.medical_organisation
            elif self.request.session['role'] == 'patient':
                user.appointed_doctors = obj.appointed_doctors
                user.date_of_birth = obj.date_of_birth
            # Example: copy profile names to user
            user.first_name = obj.first_name
            user.last_name = obj.last_name
            user.save()
        return super().form_valid(form)

class RegisterView(CreateView):
    model = get_user_model()
    form_class = StyledUserCreationForm
    success_url = "/profile/"
    template_name = "hospital/register.html"

    def form_valid(self, form):
        response = super().form_valid(form)
        login(self.request, self.object)
        return response

class RoleLoginView(LoginView):
    form_class = UsernameOnlyAuthenticationForm
    template_name = "accounts/login.html"

    def form_valid(self, form):
        """
        Log in the user without needing a password.
        """
        user = form.get_user()
        login(self.request, user)  # <-- no password check
        
        # Set role in the session
        if hasattr(user, "doctor_profile"):
            self.request.session["role"] = "doctor"
        elif hasattr(user, "patient_profile"):
            self.request.session["role"] = "patient"
        else:
            self.request.session["role"] = "unknown"

        return super().form_valid(form)

class SetupView(LoginRequiredMixin, TemplateView):
    template_name = "setup-device.html"

class SetupKeysView(LoginRequiredMixin, TemplateView):
    template_name = "setup-keys.html"

    def dispatch(self, request, *args, **kwargs):
        # Check if user already has keys setup
        from documentSigning.models import UserKeyPair
        if UserKeyPair.objects.filter(user=request.user).exists():
            return redirect('/setup/device/')
        return super().dispatch(request, *args, **kwargs)

class SetupDeviceView(LoginRequiredMixin, TemplateView):
    template_name = "setup-device.html"

    def dispatch(self, request, *args, **kwargs):
        # Check if user has keys setup
        from documentSigning.models import UserKeyPair
        if not UserKeyPair.objects.filter(user=request.user).exists():
            return redirect('/setup/keys/')
        return super().dispatch(request, *args, **kwargs)

class DevicesView(LoginRequiredMixin, TemplateView):
    template_name = "devices.html"

class PatientDoctorsView(LoginRequiredMixin, TemplateView):
    template_name = "patient-doctors.html"

    def dispatch(self, request, *args, **kwargs):
        # Only patients can access this page
        if not hasattr(request.user, 'patient_profile'):
            return redirect('/private/')
        return super().dispatch(request, *args, **kwargs)

class DoctorPatientsView(LoginRequiredMixin, TemplateView):
    template_name = "doctor-patients.html"

    def dispatch(self, request, *args, **kwargs):
        # Only doctors can access this page
        if not hasattr(request.user, 'doctor_profile'):
            return redirect('/private/')
        return super().dispatch(request, *args, **kwargs)

class MedicalRecordsView(LoginRequiredMixin, TemplateView):
    template_name = "medical-records.html"

class MedicalRecordView(LoginRequiredMixin, TemplateView):
    template_name = "record-view.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        file_id = self.kwargs.get('file_id')
        version_id = self.request.GET.get('version')  # Query parameter

        from documentSigning.models import MedicalFileVersionAccess, MedicalFile, MedicalFileVersion
        from django.shortcuts import get_object_or_404

        # Verify the file exists
        medical_file = get_object_or_404(MedicalFile, id=file_id)

        # Check user role
        is_patient = hasattr(self.request.user, 'patient_profile')

        # If version is specified, verify access to that specific version
        if version_id:
            try:
                version_id = int(version_id)

                # Get the specific version
                if is_patient:
                    # Patients can see approved and pending versions
                    version = get_object_or_404(
                        MedicalFileVersion,
                        id=version_id,
                        file=medical_file,
                        status__in=['approved', 'pending']
                    )
                else:
                    # Doctors can see approved versions OR their own pending submissions
                    from django.db.models import Q
                    version = MedicalFileVersion.objects.filter(
                        Q(id=version_id, file=medical_file, status='approved') |
                        Q(id=version_id, file=medical_file, status='pending', created_by=self.request.user)
                    ).first()

                    if not version:
                        from django.http import Http404
                        raise Http404("Version not found or access denied")

                # Verify user has access grant for this specific version
                has_access = MedicalFileVersionAccess.objects.filter(
                    version=version,
                    user=self.request.user
                ).exists()

                if not has_access:
                    from django.http import Http404
                    raise Http404("Access denied to this version")

            except (ValueError, TypeError):
                from django.http import Http404
                raise Http404("Invalid version parameter")
        else:
            # No version specified - verify access to latest version
            if is_patient:
                # Patients can see approved and pending versions
                accessible_versions = MedicalFileVersion.objects.filter(
                    file=medical_file,
                    status__in=['approved', 'pending']
                )
            else:
                # Doctors can only see approved versions
                accessible_versions = MedicalFileVersion.objects.filter(
                    file=medical_file,
                    status='approved'
                )

            # Get the latest accessible version
            latest_version = accessible_versions.order_by('-version_number').first()

            if not latest_version:
                from django.http import Http404
                raise Http404("No accessible versions found")

            # Verify user has access grant for latest version
            has_access = MedicalFileVersionAccess.objects.filter(
                version=latest_version,
                user=self.request.user
            ).exists()

            if not has_access:
                from django.http import Http404
                raise Http404("Access denied")

        # Pass file_id and optional version_id to template
        context['file_id'] = file_id
        context['version_id'] = version_id if version_id else None

        return context

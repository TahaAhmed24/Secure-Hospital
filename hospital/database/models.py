from django.db import models
from django.contrib.auth.models import User
from datetime import datetime    

class Doctor(models.Model):
    """
    Doctor profile — linked to the default Django User.
    Doctors are trusted users - profile data stored in plaintext.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="doctor_profile")
    first_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    medical_organisation = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        if self.first_name and self.last_name:
            return f"Dr. {self.first_name} {self.last_name}"
        return f"Dr. {self.user.username}"


class Patient(models.Model):
    """
    Patient profile — linked to the default Django User.
    A patient can have multiple appointed doctors.
    Profile data is encrypted client-side before being sent to server.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="patient_profile")
    # Encrypted fields (store base64-encoded encrypted data)
    first_name = models.TextField(null=True, blank=True)
    last_name = models.TextField(null=True, blank=True)
    date_of_birth = models.TextField(null=True, blank=True)
    appointed_doctors = models.ManyToManyField(Doctor, related_name="patients")

    def __str__(self):
        return f"{self.user.username}"


class AppointmentRequest(models.Model):
    """
    Appointment request from a doctor to a patient.
    Requires patient approval to establish the doctor-patient relationship.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE, related_name='appointment_requests')
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='appointment_requests')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    message = models.TextField(blank=True, help_text="Optional message from doctor")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        unique_together = [['doctor', 'patient']]  # Prevent duplicate requests

    def __str__(self):
        doctor_name = f"Dr. {self.doctor.first_name} {self.doctor.last_name}" if self.doctor.first_name else f"Dr. {self.doctor.user.username}"
        patient_name = self.patient.user.username  # Patient data is encrypted
        return f"{doctor_name} → {patient_name} ({self.status})"

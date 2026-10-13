from django import forms
from .models import MedicalRecordFile
from database.models import Patient

class MedicalRecordFileUploadForm(forms.ModelForm):
    """Form for uploading medical record files"""
    patient = forms.ModelChoiceField(
        queryset=Patient.objects.all(),
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-control',
            'id': 'patientId'
        }),
        empty_label="Select a patient"
    )
    
    exam_date = forms.DateField(
        required=True,
        widget=forms.DateInput(attrs={
            'type': 'date',
            'class': 'form-control',
            'id': 'examDate'
        })
    )
    
    file = forms.FileField(
        required=True,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'id': 'fileInput',
            'accept': '.pdf,.jpg,.jpeg,.png'
        })
    )
    
    class Meta:
        model = MedicalRecordFile
        fields = ['file', 'exam_date']
    
    def clean_file(self):
        """Validate file size and type"""
        file = self.cleaned_data.get('file')
        
        if file:
            # Check file size (10MB max)
            if file.size > 10 * 1024 * 1024:
                raise forms.ValidationError('File size must be less than 10MB')
            
            # Check file type
            allowed_types = ['application/pdf', 'image/jpeg', 'image/png']
            if file.content_type not in allowed_types:
                raise forms.ValidationError('Only PDF, JPEG, and PNG files are allowed')
        
        return file
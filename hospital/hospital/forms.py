from functools import partial

from django import forms
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
    UserCreationForm,
)
from django.contrib.auth.models import User
from django.forms import ModelForm
from django.forms.utils import ErrorList

from database.models import Doctor, Patient


# StyledErrorList = partial(ErrorList, error_class="invalid-feedback")
class StyledErrorList(ErrorList):
    def __init__(self, *args, **kwargs):
        error_class = "invalid-feedback"
        if kwargs.get("error_class") == "nonfield":
            error_class = "text-danger"
        kwargs["error_class"] = error_class
        super().__init__(*args, **kwargs)


class StyledFormMixin:
    error_css_class = "is-invalid"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, error_class=StyledErrorList, **kwargs)
        for field in self.visible_fields():
            field.field.widget.attrs["class"] = field.css_classes("form-control")


class StyledModelForm(StyledFormMixin, ModelForm):
    pass


class StyledAuthenticationForm(StyledFormMixin, AuthenticationForm):
    pass


class StyledPasswordChangeForm(StyledFormMixin, PasswordChangeForm):
    pass


class StyledPasswordResetForm(StyledFormMixin, PasswordResetForm):
    pass


class StyledSetPasswordForm(StyledFormMixin, SetPasswordForm):
    pass


ROLE_CHOICES = [
    ("patient", "Patient"),
    ("doctor", "Doctor"),
]


class StyledUserCreationForm(StyledFormMixin, UserCreationForm):
    role = forms.ChoiceField(
        choices=ROLE_CHOICES,
        required=True,
        label="Register as",
        widget=forms.Select(attrs={"class": "form-control", "id": "id_role"}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    class Meta:
        model = User
        fields = ("username", "role")


class DoctorForm(forms.ModelForm):
    class Meta:
        model = Doctor
        fields = ["first_name", "last_name", "medical_organisation"]


class PatientForm(forms.ModelForm):
    class Meta:
        model = Patient
        fields = ["first_name", "last_name", "date_of_birth"]


from django import forms
from django.contrib.auth.models import User


class UsernameOnlyAuthenticationForm(forms.Form):
    username = forms.CharField(
        label="Username", widget=forms.TextInput(attrs={"class": "form-control"})
    )

    # FIX: accept request
    def __init__(self, *args, request=None, **kwargs):
        self.request = request  # you can use it later if needed
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get("username")

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise forms.ValidationError("User not found.")

        cleaned_data["user"] = user
        return cleaned_data

    def get_user(self):
        return self.cleaned_data.get("user")

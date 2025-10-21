from django import forms
from .models import UploadedFile

class UploadForm(forms.ModelForm):
    class Meta:
        model = UploadedFile
        fields = ['file', 'subject', 'grade_level']

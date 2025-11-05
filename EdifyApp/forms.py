from django import forms
from .models import Resource


class UploadForm(forms.ModelForm):
    class Meta:
        model = Resource
        fields = ['title', 'subject', 'grade', 'file_path', 'description']

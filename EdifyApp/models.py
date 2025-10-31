import uuid
from django.db import models


# for uploading the files
class UploadedFile(models.Model):
    file = models.FileField(upload_to='uploads/')
    subject = models.CharField(max_length=100)
    grade_level = models.CharField(max_length=100)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def filename(self):
        return self.file.name.split('/')[-1]

    def file_type(self):
        return self.file.name.split('.')[-1].upper()

    def file_size(self):
        return f"{round(self.file.size / 1024 / 1024, 2)} MB"

# Create your models here.
class CustomUser(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)

    def __str__(self):
        return self.email
    

class Resource(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=255)
    subject = models.CharField(max_length=255, blank=True, null=True)
    grade = models.CharField(max_length=50, blank=True, null=True)
    file_path = models.TextField()  # Supabase public URL
    uploader = models.UUIDField(blank=True, null=True)
    thumbnail = models.TextField(blank=True, null=True)
    date_added = models.DateTimeField(auto_now_add=True)
    date_changed = models.DateTimeField(auto_now=True)
    description = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'resources'  # match Supabase table exactly
        managed = False

    def __str__(self):
        return self.title
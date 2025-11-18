import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser


class CustomUser(AbstractUser):
    supabase_id = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(unique=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email
    

class UploadedFile(models.Model):
    file = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)


class Resource(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=255)
    subject = models.CharField(max_length=255, blank=True, null=True)
    grade = models.CharField(max_length=50, blank=True, null=True)
    file_path = models.TextField()  # Supabase file path
    uploader = models.UUIDField(blank=True, null=True)
    thumbnail = models.TextField(blank=True, null=True)
    date_added = models.DateTimeField(auto_now_add=True)
    date_changed = models.DateTimeField(auto_now=True)
    description = models.TextField(null=True, blank=True)

    # ✅ New fields for feature compatibility
    is_favorite = models.BooleanField(default=False)  # For favorites feature
    file_type = models.CharField(max_length=50, blank=True, null=True)
    file_size = models.CharField(max_length=50, blank=True, null=True)

    class Meta:
        db_table = 'resources'
        managed = False  # keep False if this table already exists in Supabase

    def __str__(self):
        return self.title or "Untitled"

    # ✅ Helper methods (like UploadedFile)
    def get_filename(self):
        """Return the filename extracted from the file_path."""
        if self.file_path:
            return self.file_path.split('/')[-1]
        return "Unknown File"

    def get_file_type(self):
        """Extract file extension and return in uppercase."""
        filename = self.get_filename()
        if '.' in filename:
            return filename.split('.')[-1].upper()
        return "UNKNOWN"

    def get_file_size(self):
        """If you store size later, display formatted MB text."""
        return self.file_size or "Unknown Size"
    


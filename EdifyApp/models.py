import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone


# ✅ 1. Custom Manager to fix "missing username" error
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        
        email = self.normalize_email(email)
        
        # Since AbstractUser implies a 'username' field exists, 
        # we autofill it with the email to avoid DB errors.
        if 'username' not in extra_fields:
            extra_fields['username'] = email

        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)

# ✅ 2. Your Custom User Model
class CustomUser(AbstractUser):
    # Note: AbstractUser already includes first_name, last_name, and username.
    # We only define what we want to override or add.
    
    supabase_id = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(unique=True) # Override to make unique

    # Connect the Custom Manager
    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    # We keep this empty because 'email' is the identifier
    # and password is required by default.
    REQUIRED_FIELDS = [] 

    # Add these lines to your CustomUser model
    bio = models.TextField(blank=True, null=True)
    profile_picture = models.URLField(max_length=500, blank=True, null=True) # Stores the Supabase URL

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
    


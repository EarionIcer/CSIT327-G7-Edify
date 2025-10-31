
# views.py 


from datetime import datetime
import os
import logging
from django.shortcuts import render, redirect
from django.http import HttpResponse
from supabase import create_client
from django.conf import settings   
from .models import Resource, UploadedFile
from .forms import UploadForm 
from .supabase_client import supabase
from django.http import JsonResponse
import uuid
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.contrib import messages
from datetime import datetime
import uuid

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY") 
supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

# for uploading files
def uploads(request):
    if request.method == 'POST':
        file = request.FILES['file']
        subject = request.POST.get('subject')
        grade_level = request.POST.get('grade_level')

        # Generate unique filename
        unique_name = f"{uuid.uuid4()}_{file.name}"

        # Upload to Supabase storage
        supabase.storage.from_('uploads').upload(unique_name, file.read())

        # Insert file metadata into Supabase table
        supabase.table('uploaded_files').insert({
            'file_name': file.name,
            'file_path': unique_name,
            'subject': subject,
            'grade_level': grade_level,
        }).execute()

        return redirect('uploads')

    # Fetch all uploaded files
    files = supabase.table('uploaded_files').select('*').execute().data
    return render(request, 'uploads.html', {'files': files})

# add files
def add_files(request):
    """Render the Add Files page"""
    return render(request, "addfiles.html")

# API for the upload files
def upload_file(request):
    if request.method == "POST" and request.FILES.get('file'):
        title = request.POST.get('title', '').strip()
        subject = request.POST.get('subject', '').strip()
        grade = request.POST.get('grade', '').strip()
        description = request.POST.get('description', '').strip()
        uploader = request.POST.get('uploader')  # UUID of user
        file = request.FILES['file']
        thumbnail = request.POST.get('thumbnail')  # optional

        # 1️⃣ Validate required fields
        missing_fields = []
        if not title:
            missing_fields.append("title")
        if not subject:
            missing_fields.append("subject")
        if not grade:
            missing_fields.append("grade")
        if not description:
            missing_fields.append("description")

        if missing_fields:
            return JsonResponse({
                "error": f"The following fields cannot be empty: {', '.join(missing_fields)}"
            }, status=400)

        file_name = f"{uuid.uuid4()}_{file.name}"  # unique filename

        try:
            # debug logger to help diagnose RLS / key issues
            logger = logging.getLogger(__name__)
            try:
                # show a short prefix of the configured Supabase key so we can tell anon vs service_role in logs
                key_preview = (settings.SUPABASE_KEY or "")[:20]
            except Exception:
                key_preview = "(no key)"
            logger.debug("Supabase key preview: %s", key_preview)
            # 2️⃣ Upload file to Supabase Storage
            upload_response = supabase.storage.from_(settings.SUPABASE_BUCKET).upload(file_name, file.read())

            if isinstance(upload_response, dict) and 'error' in upload_response:
                return JsonResponse({'error': upload_response['error']['message']}, status=400)

            # 3️⃣ Get public URL for the uploaded file
            public_url = supabase.storage.from_(settings.SUPABASE_BUCKET).get_public_url(file_name)

            # 4️⃣ Insert metadata into Supabase table
            resource_data = {
                "id": str(uuid.uuid4()),
                "title": title,
                "subject": subject,
                "grade": grade,
                "file_path": public_url,
                "uploader": uploader,
                "thumbnail": thumbnail or None,
                "date_added": datetime.utcnow().isoformat(),
                "date_changed": datetime.utcnow().isoformat(),
                "description": description,
            }

            insert_response = supabase.table("resources").insert(resource_data).execute()
            # Log the raw response — Supabase client returns .data and may set .error when RLS blocks
            logger.debug("Supabase insert_response: %s", getattr(insert_response, '__dict__', str(insert_response)))

            # If Supabase returned an error payload, surface it immediately for diagnosis
            err = None
            if hasattr(insert_response, 'error') and insert_response.error:
                err = insert_response.error
            elif isinstance(insert_response, dict) and insert_response.get('error'):
                err = insert_response.get('error')
            if err:
                logger.error("Supabase insert error: %s", err)
                return JsonResponse({'error': 'Supabase insert failed', 'details': str(err)}, status=400)

            # 5️⃣ Optional: store locally in Django DB for admin view
            if insert_response.data:
                Resource.objects.create(
                    id=insert_response.data[0]['id'],
                    title=title,
                    subject=subject,
                    grade=grade,
                    file_path=public_url,
                    uploader=uploader,
                    thumbnail=thumbnail,
                    description=description,
                )

                return JsonResponse({
                    'message': 'File uploaded and saved to Supabase!',
                    'url': public_url,
                    'resource': insert_response.data
                })
            else:
                return JsonResponse({'error': 'Failed to insert metadata into Supabase'}, status=400)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'No file provided or invalid request method'}, status=400)



# EdifyApp/views.py
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import get_user_model
from datetime import datetime
import uuid
from EdifyProject.settings import supabase

User = get_user_model()

def register(request):
    if request.method == "POST":
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        if password != confirm_password:
            return render(request, "register.html", {"error": "Passwords do not match!"})

        try:
            # 1️⃣ Create in Supabase Auth
            auth_response = supabase.auth.admin.create_user({
                "email": email,
                "password": password,
                "email_confirm": True,  # optional: skip email verification
                "user_metadata": {"first_name": first_name, "last_name": last_name}
            })
            user_data = auth_response.user

            if not user_data:
                return render(request, "register.html", {"error": "Supabase Auth creation failed!"})

            # 2️⃣ Save in Django model
            local_user = User.objects.create_user(
                username=email,
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=password,
                supabase_id=user_data.id
            )

            messages.success(request, f"Account created successfully for {email}!")
            return redirect("login")

        except Exception as e:
            print("❌ Registration error:", e)
            messages.error(request, "Failed to register user.")
            return render(request, "register.html")

    return render(request, "register.html")





def login_view(request):
    if request.method == "POST":
        email = request.POST.get("emailAd")
        password = request.POST.get("password")

        try:
            # 🔐 Authenticate with Supabase
            res = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            user = res.user
            session = res.session

            if not user:
                messages.error(request, "Invalid email or password.")
                return render(request, "login.html")

            # ✅ Store session info in Django session
            request.session["user_email"] = user.email
            request.session["access_token"] = session.access_token
            request.session["refresh_token"] = session.refresh_token
            request.session.set_expiry(3600)  # expires after 1 hour

            messages.success(request, f"Welcome {user.email}!")
            return redirect("overview")

        except Exception as e:
            print("Supabase login error:", e)
            messages.error(request, "Invalid credentials!")
            return render(request, "login.html")

    return render(request, "login.html") 


def navbar(request):
    user = request.session.get("user")
    if not user:
        return redirect("login")

    success_message = request.session.pop("success_message", None)
    return render(request, "navbar.html", {"success": success_message})

def overview(request):
    return render(request, "overview.html")

def uploads(request):
    return render(request, "uploads.html")

def favorites(request):
    return render(request, "favorites.html")

def profiled(request):
    return render(request, 'profiled.html')

def about(request):
    return render(request, 'about.html')


# def logout_view(request):
#     request.session.flush()
#     return redirect("login")
def logout_view(request):
    # Optional: revoke Supabase session
    access_token = request.session.get("access_token")
    if access_token:
        try:
            supabase.auth.sign_out()
        except Exception:
            pass

    request.session.flush()  # removes all session data
    messages.success(request, "You have been logged out.")
    return redirect("login")

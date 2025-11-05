
# views.py 

from .models import CustomUser
from datetime import datetime
import os
import logging
from sqlite3 import IntegrityError
from django.shortcuts import render, redirect
from django.http import HttpResponse
from supabase import create_client, Client
from django.conf import settings   
from .models import Resource
from .forms import UploadForm 
from django.shortcuts import redirect, get_object_or_404
from django.contrib import messages
from .supabase_client import supabase
from django.http import JsonResponse
import uuid
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

from django.db import ProgrammingError
from django.db.models import Q
from django.contrib import messages
from django.contrib.auth import login
# from django.contrib.auth.models import User
from django.contrib import messages
from datetime import datetime
from django.utils import timezone
import uuid
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.http import JsonResponse
from .supabase_client import supabase
from django.shortcuts import render
from django.contrib.auth.decorators import login_required


SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY") 
supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)



# API for the upload files
@login_required
def upload_file(request):
    if request.method == "POST":
        uploaded_file = request.FILES.get("file")
        title = request.POST.get("title")
        subject = request.POST.get("subject")
        grade = request.POST.get("grade")
        description = request.POST.get("description")

        if not uploaded_file:
            return JsonResponse({"error": "No file uploaded."}, status=400)

        try:
            # Generate unique file name and path
            file_name = f"{uuid.uuid4()}_{uploaded_file.name}"
            file_path = f"user_uploads/{request.user.id}/{file_name}"

            # Get file info
            _, file_extension = os.path.splitext(uploaded_file.name)
            file_type = uploaded_file.content_type or file_extension

            # ✅ Upload file to Supabase Storage
            upload_res = supabase.storage.from_(settings.SUPABASE_BUCKET).upload(
                file_path, uploaded_file.read()
            )

            if isinstance(upload_res, dict) and upload_res.get("error"):
                return JsonResponse({"error": upload_res["error"]["message"]}, status=500)

            # ✅ Get public file URL
            public_url = supabase.storage.from_(settings.SUPABASE_BUCKET).get_public_url(file_path)

            # ✅ Insert file metadata into Supabase table
            resource_data = {
                "id": str(uuid.uuid4()),
                "title": title,
                "subject": subject,
                "grade": grade,
                "description": description,
                "file_path": public_url,
                "file_size": f"{round(uploaded_file.size / 1024, 2)} KB",
                "file_type": file_type,
                "user_id": str(request.user.id),
                "date_added": timezone.now().isoformat(),

            }

            supabase.table("resources").insert(resource_data).execute()

            return JsonResponse({"message": "File uploaded successfully!"})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method."}, status=405)




# EdifyApp/views.py
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import get_user_model
from datetime import datetime
import uuid
from EdifyProject.settings import supabase

User = get_user_model()

from django.contrib.auth import login as django_login
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect
from django.contrib import messages

def register(request):
    """
    Handles user registration by validating input, checking local database
    for existing email, creating the user in Supabase, and finally
    creating the local user profile.
    """
    if request.method == "POST":
        # 1. Get Data from POST request
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")
        
        # Basic input validation can go here (e.g., checking if fields are empty)

        # 2. Check if Passwords Match
        if password != confirm_password:
            messages.error(request, "❌ Passwords do not match! Please try again.")
            # Keep the form data for better user experience (optional: pass context)
            return render(request, "register.html")

        # 3. Check for Existing Email in Local DB (for immediate error)
        # **This addresses your specific request to error when the email is already created locally.**
        if CustomUser.objects.filter(email__iexact=email).exists():
            messages.error(request, "📧 An account with this email already exists!")
            return render(request, "register.html")

        try:
            # 4. Create User in Supabase
            auth_response = supabase.auth.admin.create_user({
                "email": email,
                "password": password,
                "email_confirm": True, # Ensure this is what you want
                "user_metadata": {
                    "first_name": first_name,
                    "last_name": last_name
                }
            })
            
            # The Supabase Python library might raise an HTTPError or similar exception 
            # if the email already exists in Supabase, which is caught below.

            user_data = auth_response.user

            # 5. Check Supabase Response for Failure
            if not user_data:
                # This check might be redundant if the library raises exceptions, 
                # but it's a good safeguard.
                messages.error(request, "⚠️ Supabase registration failed! The email might already exist or there was a server error.")
                return render(request, "register.html")

            # 6. Create Local User Profile
            # NOTE: Storing the hashed password with `make_password` is correct.
            local_user = CustomUser.objects.create(
                email=email,
                # It's safer to use a unique identifier from Supabase if available, 
                # but using email as username is common.
                username=email, 
                first_name=first_name,
                last_name=last_name,
                password=make_password(password), # Store the HASHED password
                supabase_id=user_data.id # Store the Supabase UUID
            )

            # 7. Log In the User
            login(request, local_user)
            request.session["user_email"] = email
            # Consider using Django's standard session management and not setting 
            # the expiry manually unless you have a specific reason.
            request.session.set_expiry(3600) # Session expires in 1 hour (3600 seconds)

            # 8. Redirect to the Overview Page
            # **This is the most common failure point for your issue.**
            messages.success(request, f"🎉 Welcome, {first_name}! Your account has been created.")
            return redirect("overview")

        except Exception as e:
            # Catch exceptions from Supabase or the local DB operation.
            # print(traceback.format_exc()) # Uncomment this for detailed debugging!
            print("ERROR during registration:", e) 

            # **CRITICAL:** If the Supabase call fails because the email already 
            # exists in Supabase (but not locally yet), this catches it.
            messages.error(request, "🚨 Failed to register. An unexpected error occurred or the email is already registered in our system. Try again!")
            return render(request, "register.html")

    # If request is GET, just render the empty form
    return render(request, "register.html")


def toggle_favorite(request, pk):
    file = get_object_or_404(UploadedFile, pk=pk)
    file.is_favorite = not file.is_favorite
    file.save()

    if file.is_favorite:
        messages.success(request, f'"{file.title}" added to favorites.')
    else:
        messages.info(request, f'"{file.title}" removed from favorites.')

    return redirect('uploads')



def owsearch(request):
    query = request.GET.get('q', '').strip()
    results = []
    message = ""

    if query:
        try:
            results = UploadedFile.objects.filter(
                Q(file__icontains=query) |
                Q(subject__icontains=query) |
                Q(grade_level__icontains=query)
            )
        except ProgrammingError:
            # DB table missing — avoid 500 and show friendly message
            results = []
            message = f'File named "{query}" can’t be found. (Database table not present yet.)'
        else:
            if not results.exists():
                message = f'File named "{query}" can’t be found.'
    else:
        message = "Enter a keyword to search your files."

    return render(request, 'owsearch.html', {
        'query': query,
        'results': results,
        'message': message,
    })



def login_view(request):
    if request.method == "POST":
        email = request.POST.get("emailAd")
        password = request.POST.get("password")

        try:
            res = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            if not res.user:
                error_msg = res.error.message.lower() if res.error else ""

                if "invalid login credentials" in error_msg:
                    messages.error(request, "Incorrect password.")
                elif "email" in error_msg:
                    messages.error(request, "Invalid Gmail.")
                else:
                    messages.error(request, "Invalid credentials, please try again.")

                return redirect("login")

            # ✅ Successful login
            user = res.user
            session = res.session

            request.session["user_email"] = user.email
            request.session["access_token"] = session.access_token
            request.session["refresh_token"] = session.refresh_token
            request.session.set_expiry(3600)

            
            return redirect("overview")

        except Exception as e:
            print("Supabase login error:", e)
            messages.error(request, "Invalid credentials!")
            return redirect("login")

    return render(request, "login.html")


def navbar(request):
    user = request.session.get("user")
    if not user:
        return redirect("login")

    success_message = request.session.pop("success_message", None)
    return render(request, "navbar.html", {"success": success_message})

def overview(request):
    try:
        user = request.user  # ✅ Current logged-in user

        # Step 1: Welcome message
        welcome_msg = request.session.pop("welcome_message", None)
        if welcome_msg:
            messages.success(request, welcome_msg)

        # Step 2: Fetch only this user’s resources
        response = supabase.table("resources").select("*").eq("user_id", str(user.id)).execute()
        resources = response.data or []

        # Step 3: Compute stats
        total_uploads = len(resources)
        favorites_count = 0  # (optional: implement favorites later)
        subjects = {r['subject'] for r in resources if r.get('subject')}
        subjects_count = len(subjects)

        # Total storage
        total_kb = sum([
            float(r.get('file_size', '0').split()[0])
            for r in resources if r.get('file_size')
        ])
        total_storage = f"{round(total_kb / 1024, 2)} MB" if total_kb > 1024 else f"{total_kb} KB"

        # Step 4: Recent uploads
        recent_uploads = sorted(resources, key=lambda x: x.get('date_added', ''), reverse=True)[:5]

        # Step 5: Context for template
        context = {
            "total_uploads": total_uploads,
            "favorites_count": favorites_count,
            "subjects_count": subjects_count,
            "total_storage": total_storage,
            "recent_uploads": recent_uploads,
            "resources": resources,
        }

        return render(request, "overview.html", context)

    except Exception as e:
        return render(request, "overview.html", {"error": str(e)})

# for uploading files
def uploads(request):
    try:
        # Only get files uploaded by the logged-in user
        user_id = str(request.user.id)

        response = (
            supabase.table("resources")
            .select("*")
            .eq("user_id", user_id)
            .execute()
        )
        resources = response.data or []

        # Send them to the template
        return render(request, "uploads.html", {"resources": resources})
    except Exception as e:
        # In case Supabase or network fails
        return render(request, "uploads.html", {"error": str(e)})

    
# add files
def add_files(request):
    if request.method == "POST":
        title = request.POST.get("title")
        subject = request.POST.get("subject")
        grade = request.POST.get("grade")
        description = request.POST.get("description")
        uploaded_file = request.FILES.get("file")

        if not uploaded_file:
            messages.error(request, "No file selected.")
            return redirect("addfiles")

        try:
            # ✅ Upload file to Supabase Storage
            file_name = f"{uuid.uuid4()}_{uploaded_file.name}"
            upload_res = supabase.storage.from_(settings.SUPABASE_BUCKET).upload(
                file_name, uploaded_file.read()
            )

            # Check for errors
            if isinstance(upload_res, dict) and upload_res.get("error"):
                messages.error(request, f"Upload failed: {upload_res['error']['message']}")
                return redirect("addfiles")

            # ✅ Get public file URL
            public_url = supabase.storage.from_(settings.SUPABASE_BUCKET).get_public_url(file_name)

            # ✅ Insert into 'resources' table in Supabase
            resource_data = {
                "id": str(uuid.uuid4()),
                "title": title,
                "subject": subject,
                "grade": grade,
                "description": description,
                "file_path": public_url,
                "file_size": f"{round(uploaded_file.size / 1024, 2)} KB",
                "user_id": str(request.user.id),  # ✅ Now linked to logged-in user
                "date_added": timezone.now().isoformat(),  # ✅ safer and timezone-aware
            }
            supabase.table("resources").insert(resource_data).execute()

            messages.success(request, "File uploaded successfully!")
            return redirect("uploads")

        except Exception as e:
            messages.error(request, f"Upload error: {e}")
            return redirect("addfiles")

    return render(request, "addfiles.html")


def view_file(request, pk):
    file = get_object_or_404(UploadedFile, pk=pk)
    return render(request, 'view_file.html', {'file': file})

def edit_file(request, pk):
    file = get_object_or_404(UploadedFile, pk=pk)
    if request.method == 'POST':
        form = UploadedFileForm(request.POST, request.FILES, instance=file)
        if form.is_valid():
            form.save()
            return redirect('uploads')  # redirects back to uploads page
    else:
        form = UploadedFileForm(instance=file)
    return render(request, 'edit_file.html', {'form': form, 'file': file})

def delete_file(request, pk):
    """
    Delete a file from Supabase storage and database.
    """
    if request.method == "POST":
        file = get_object_or_404(UploadedFile, pk=pk)
        file.file.delete(save=False)  # delete the actual uploaded file from storage
        file.delete()  # remove the database record
        messages.success(request, f"{file.subject} file deleted successfully!")
        return redirect("uploads")
    else:
        messages.error(request, "Invalid request method.")
        return redirect("uploads")


def favorites(request):
    favorites = UploadedFile.objects.filter(is_favorite=True)
    return render(request, 'favorites.html', {'favorites': favorites})


def profiled(request):
    return render(request, 'profiled.html')

def about(request):
    return render(request, 'about.html')


def logout_view(request):
    # Optional: revoke Supabase session
    access_token = request.session.get("access_token")
    if access_token:
        try:
            supabase.auth.sign_out()
        except Exception:
            pass

    # ✅ Add message before flushing session
    messages.success(request, "You have been logged out.")

    # Then clear session
    request.session.flush()

    return redirect("login")


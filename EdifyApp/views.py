
# views.py 

# from email.utils import localtime
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
from django.utils.timezone import localtime
from django.shortcuts import redirect, get_object_or_404
from django.contrib import messages
from .supabase_client import supabase
from django.http import JsonResponse
import uuid
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth.hashers import check_password
from django.utils.timezone import make_aware
from django.contrib.auth.decorators import login_required
from django.conf import settings
from .models import UploadedFile



from django.db import ProgrammingError
from django.db.models import Q
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.humanize.templatetags.humanize import naturaltime
from django.utils.timezone import now
from django.utils.timesince import timesince
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
import requests
from django.http import HttpResponse, Http404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.shortcuts import render, redirect
from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.http import JsonResponse
from django.contrib.auth.hashers import make_password
from .models import CustomUser




CustomUser = get_user_model()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY") 
supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)



# API for the upload files

def upload_file(request):
    if not request.session.get("user_id"):
        return JsonResponse({"error": "You must be logged in to upload."}, status=401)
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
            file_type = file_extension.lower().lstrip('.')  # ✅ always returns 'pdf', 'txt', 'docx'

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
                "user_id": request.session.get("user_id"),  # ✅ use session user_id from Supabase
                "date_added": timezone.now().isoformat(),
            }

            supabase.table("resources").insert(resource_data).execute()

            return JsonResponse({"message": "File uploaded successfully!"})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method."}, status=405)


def edit_file(request, file_id):
    """
    Edit resource metadata and optionally replace uploaded file.
    Automatically deletes old file in Supabase storage if a new file is uploaded.
    """

    # ✅ Check login
    user_id = request.session.get("user_id")
    if not user_id:
        messages.error(request, "Please log in first.")
        return redirect("login")

    # ✅ Fetch existing file record
    try:
        resp = supabase.table("resources").select("*").eq("id", str(file_id)).execute()
    except Exception as e:
        messages.error(request, f"Error fetching file: {e}")
        return redirect("uploads")

    if not resp.data:
        messages.error(request, "File not found.")
        return redirect("uploads")

    resource = resp.data[0]

    # ✅ Ensure this file belongs to the logged-in user
    if str(resource.get("user_id")) != str(user_id):
        messages.error(request, "You don't have permission to edit this file.")
        return redirect("uploads")

    # ✅ Handle update
    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        subject = request.POST.get("subject", "").strip()
        grade = request.POST.get("grade", "").strip()
        description = request.POST.get("description", "").strip()
        uploaded_file = request.FILES.get("file")

        # Build update payload
        update_data = {
            "title": title,
            "subject": subject,
            "grade": grade,
            "description": description,
        }

        # ✅ Handle file replacement
        if uploaded_file:
            try:
                # 🔹 1. Delete the old file first if it exists
                old_file_path = resource.get("file_path")
                if old_file_path:
                    # Extract path after the bucket name
                    # e.g. https://xyz.supabase.co/storage/v1/object/public/uploads/userid/file.pdf
                    old_file_key = old_file_path.split("/uploads/")[-1]  # 'userid/file.pdf'
                    print("🗑️ Deleting old file:", old_file_key)

                    try:
                        supabase.storage.from_(settings.SUPABASE_BUCKET).remove([old_file_key])
                    except Exception as delete_err:
                        print("⚠️ Warning: could not delete old file:", delete_err)

                # 🔹 2. Upload the new file
                file_name = f"{user_id}/{uuid.uuid4()}_{uploaded_file.name}"
                result = supabase.storage.from_(settings.SUPABASE_BUCKET).upload(
                    file_name,
                    uploaded_file.read(),
                )

                if isinstance(result, dict) and result.get("error"):
                    raise Exception(result["error"].get("message", result["error"]))

                public = supabase.storage.from_(settings.SUPABASE_BUCKET).get_public_url(file_name)
                public_url = public.get("publicUrl") if isinstance(public, dict) else public

                # 🔹 3. Update database record with new file info
                update_data.update({
                    "file_path": public_url,
                    "file_type": os.path.splitext(uploaded_file.name)[1].lower().lstrip("."),
                    "file_size": f"{round(uploaded_file.size / 1024, 2)} KB",
                })

            except Exception as e:
                messages.error(request, f"Upload failed: {e}")
                return redirect("edit_file", file_id=file_id)

        # ✅ Perform DB update
        try:
            print("📤 About to update file:", file_id)
            print("🔧 Data being sent to Supabase:", update_data)

            upd = supabase.table("resources").update(update_data).eq("id", str(file_id)).execute()
            print("🔍 UPDATE RESULT:", upd)

            if isinstance(upd, dict) and upd.get("error"):
                raise Exception(upd["error"].get("message", upd["error"]))

        except Exception as e:
            print("❌ Update failed with exception:", e)
            messages.error(request, f"Error updating file: {e}")
            return redirect("edit_file", file_id=file_id)

        messages.success(request, "File updated successfully.")
        return redirect("uploads")

    # ✅ GET: render form
    return render(request, "edit_file.html", {"file": resource})


def forgot_password_view(request):
    # Just render the page — actual logic handled by AJAX
    return render(request, "forgot_password.html")


def reset_password_view(request):
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)

    action = request.POST.get("action")

    # ----------------------------
    # 1️⃣ Check Email Exists
    # ----------------------------
    if action == "check_email":
        email = request.POST.get("email").strip().lower()
        user = CustomUser.objects.filter(email=email).first()

        if user:
            return JsonResponse({"status": "success", "message": "Email found!"})
        else:
            return JsonResponse({"status": "error", "message": "This email is not registered."})

    # ----------------------------
    # 2️⃣ Reset Password
    # ----------------------------
    elif action == "reset_password":
        email = request.POST.get("email")
        new_password = request.POST.get("password")

        user = CustomUser.objects.filter(email=email).first()
        if not user:
            return JsonResponse({"status": "error", "message": "User not found."})

        # Hash password correctly
        user.password = make_password(new_password)
        user.save()

        return JsonResponse({"status": "success", "message": "Password updated!"})

    return JsonResponse({"status": "error", "message": "Unknown action"}, status=400)



def toggle_favorite(request, id):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Please log in first.")
            return redirect("login")

        # ✅ Fetch the resource that belongs to this user
        res = supabase.table("resources").select("is_favorite").eq("id", str(id)).eq("user_id", user_id).single().execute()

        if not res.data:
            messages.error(request, "File not found or unauthorized access.")
            return redirect("uploads")

        current_status = res.data.get("is_favorite", False)
        new_status = not current_status

        # ✅ Update favorite status
        supabase.table("resources").update({"is_favorite": new_status}).eq("id", str(id)).execute()

        if new_status:
            messages.success(request, "File added to favorites ⭐")
        else:
            messages.info(request, "File removed from favorites.")

        return redirect("uploads")

    except Exception as e:
        messages.error(request, f"Error updating favorite: {e}")
        return redirect("uploads")





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
    if request.method == "POST":
        first_name = request.POST.get("first_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        email = request.POST.get("email", "").strip().lower()
        password = request.POST.get("password", "")
        confirm_password = request.POST.get("confirm_password", "")

        # --- 1️⃣ Basic validation ---
        if not all([first_name, last_name, email, password, confirm_password]):
            messages.error(request, "⚠️ Please fill out all fields.")
            return render(request, "register.html")

        if password != confirm_password:
            messages.error(request, "❌ Passwords do not match.")
            return render(request, "register.html")

        # --- 2️⃣ Check for duplicate email ---
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "📧 Email already exists.")
            return render(request, "register.html")

        try:
            # --- 3️⃣ Create local Django user only ---
            hashed_pw = make_password(password)
            local_user = CustomUser.objects.create(
                email=email,
                username=email,
                first_name=first_name,
                last_name=last_name,
                password=hashed_pw,
            )

            # --- 4️⃣ Log the user in ---
            login(request, local_user)

            # ✅ Store Django’s integer ID in session
            request.session["user_id"] = local_user.id  
            request.session["user_email"] = local_user.email

            messages.success(request, f"🎉 Welcome, {first_name}! Your account has been created.")
            return redirect("overview")

        except Exception as e:
            print("❌ Registration error:", e)
            messages.error(request, "🚨 Registration failed. Please try again later.")
            return render(request, "register.html")

    return render(request, "register.html")






def owsearch(request):
    query = request.GET.get("q", "").strip()
    show_all = "show_all" in request.GET
    message = ""

    # ✅ Get user_id from session
    user_id = request.session.get("user_id")
    if not user_id:
        messages.error(request, "User not logged in.")
        return redirect("login")

   

    try:
        # ✅ Fetch all resources for this user
        response = supabase.table("resources").select("*").eq("user_id", user_id).execute()
        resources = response.data or []

        # ✅ Convert Supabase timestamps to Python datetime
        for r in resources:
            date_str = r.get("date_added")
            if date_str:
                try:
                    r["date_added"] = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                except Exception:
                    pass  # Leave as-is if invalid format

        # ✅ Apply search or "View All"
        if query:
            results = [
                r for r in resources
                if query.lower() in (
                    f"{r.get('title', '').lower()} {r.get('subject', '').lower()} "
                    f"{r.get('grade', '').lower()} {r.get('file_type', '').lower()}"
                )
            ]
            message = f'Showing results for "{query}".' if results else f'No files found for "{query}".'

        elif show_all:
            results = sorted(resources, key=lambda x: x.get("date_added", ""), reverse=True)
            message = "Showing all your uploaded files."

        else:
            results = []
            message = ""  # Don't show anything if no search or show_all

    except Exception as e:
        results = []
        message = f"Error fetching files: {str(e)}"

    return render(request, "owsearch.html", {
        "query": query,
        "results": results,
        "message": message,
        "show_all": show_all,
    })

def login_view(request):
    # ✅ If already logged in, redirect
    if request.user.is_authenticated:
        return redirect("overview")

    # Load saved email from cookie for auto-fill
    saved_email = request.COOKIES.get("saved_email", "")

    if request.method == "POST":
        email = request.POST.get("emailAd").strip().lower()  # ← using emailAd
        password = request.POST.get("password")
        remember_me = request.POST.get("remember_me")  # Checkbox value

        try:
            user = CustomUser.objects.filter(email=email).first()

            if not user:
                messages.error(request, "❌ Account not found.")
                return redirect("login")

            if not check_password(password, user.password):
                messages.error(request, "⚠️ Incorrect password.")
                return redirect("login")

            # ✅ Log in the user
            login(request, user)

            # Remember Me expiration
            if remember_me:
                request.session.set_expiry(60 * 60 * 24 * 30)  # 30 days
            else:
                request.session.set_expiry(0)  # Close browser = logout

            # Create response to set cookie
            # Redirect based on role
            
            response = redirect("overview")


            # Save email in cookie for auto-fill (works after logout)
            response.set_cookie("saved_email", email, max_age=60 * 60 * 24 * 30)

            # Store user info in session
            request.session["user_id"] = user.id
            request.session["user_email"] = user.email

            messages.success(request, f"👋 Welcome back, {user.first_name or user.email}!")

            return response

        except Exception as e:
            print("⚠️ Login error:", e)
            messages.error(request, "An error occurred during login.")
            return redirect("login")

    # Send saved email to template
    return render(request, "login.html", {"saved_email": saved_email})



def download_file(request, file_id):
    # ✅ Check user session
    user_id = request.session.get("user_id")
    if not user_id:
        return redirect("login")


    try:
        # ✅ Get file data by id
        response = supabase.table("resources").select("*").eq("id", str(file_id)).single().execute()
        file_data = response.data

        if not file_data:
            raise Http404("File not found.")

        # ✅ Ensure user owns the file
        if file_data["user_id"] != user_id:
            return HttpResponse("Unauthorized access.", status=403)

        # ✅ Get the file URL and name
        file_url = file_data["file_path"]
        file_name = file_data["title"] or "downloaded_file"
        file_type = file_data.get("file_type", "bin")

        # ✅ Stream file from Supabase public URL
        file_response = requests.get(file_url)
        if file_response.status_code != 200:
            return HttpResponse("Error downloading file from Supabase.", status=500)

        # ✅ Prepare response for browser download
        response = HttpResponse(
            file_response.content,
            content_type="application/octet-stream"
        )
        response["Content-Disposition"] = f'attachment; filename="{file_name}.{file_type}"'
        return response

    except Exception as e:
        print("Download error:", str(e))
        raise Http404("Error downloading file.")


def file_detail(request, file_id):
    # Get Supabase user ID from session
    user_id = request.session.get("user_id")
    if not user_id:
        messages.error(request, "You must be logged in to view files.")
        return redirect("login")

    # Fetch file from Supabase
    file_data = (
        supabase.table("resources")
        .select("*")
        .eq("id", str(file_id))
        .eq("user_id", user_id)
        .execute()
    )

    if not file_data.data:
        messages.error(request, "File not found.")
        return redirect("owsearch")

    file = file_data.data[0]
    return render(request, "file_detail.html", {"file": file})



def navbar(request):
    user = request.session.get("user")
    if not user:
        return redirect("login")

    success_message = request.session.pop("success_message", None)
    return render(request, "navbar.html", {"success": success_message})


def overview(request):
    try:
        # ✅ Get Supabase user_id from session
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Please log in to view your dashboard.")
            return redirect("login")

        # ✅ Step 1: Fetch all this user’s resources
        response = supabase.table("resources").select("*").eq("user_id", str(user_id)).execute()
        resources = response.data or []

        # ✅ Step 2: Compute stats
        total_uploads = len(resources)

        favorites = [r for r in resources if r.get("is_favorite")]
        favorites_count = len(favorites)

        subjects = {r['subject'] for r in resources if r.get('subject')}
        subjects_count = len(subjects)

        # ✅ Compute total storage
        total_kb = sum([
            float(r.get('file_size', '0').split()[0])
            for r in resources if r.get('file_size')
        ])
        total_storage = f"{total_kb / 1024:.2f} MB" if total_kb > 1024 else f"{total_kb:.2f} KB"

        # ✅ Step 3: Convert date_added → human readable “time ago”
        for r in resources:
            date_str = r.get("date_added")
            if date_str:
                try:
                    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    time_diff = timesince(dt, now())
                    r["time_ago"] = time_diff.split(",")[0] + " ago"
                except Exception:
                    r["time_ago"] = ""
            else:
                r["time_ago"] = ""

        # ✅ Step 4: Sort by newest and pick top 5
        recent_uploads = sorted(resources, key=lambda x: x.get('date_added', ''), reverse=True)[:5]

        # ✅ Step 5: Context for template
        context = {
            "total_uploads": total_uploads,
            "favorites_count": favorites_count,
            "subjects_count": subjects_count,
            "total_storage": total_storage,
            "recent_uploads": recent_uploads,
            "favorites": favorites,
        }

        return render(request, "overview.html", context)

    except Exception as e:
        return render(request, "overview.html", {"error": str(e)})


# for uploading files
def uploads(request):
    try:
        # ✅ Get logged-in user's ID from session
        user_id = request.session.get("user_id")

        if not user_id:
            return redirect("login")

        # ✅ Initialize Supabase client (if not globally defined)
        supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

        # ✅ Fetch all files uploaded by this user
        response = (
            supabase.table("resources")
            .select("*")
            .eq("user_id", user_id)
            .execute()
        )
        resources = response.data or []

        # ✅ Generate dynamic subject list
        subjects = sorted(list({r.get("subject", "") for r in resources if r.get("subject")}))

        # ✅ Handle subject filtering
        selected_subject = request.GET.get("subject", "All")
        if selected_subject != "All":
            resources = [r for r in resources if r.get("subject") == selected_subject]

        # ✅ Handle search functionality (optional)
        query = request.GET.get("q", "").strip()
        if query:
            resources = [
                r for r in resources
                if query.lower() in r.get("title", "").lower()
                or query.lower() in r.get("subject", "").lower()
                or query.lower() in r.get("grade", "").lower()
            ]

        context = {
            "resources": resources,
            "subjects": subjects,
            "selected_subject": selected_subject,
            "query": query,
        }

        return render(request, "uploads.html", context)

    except Exception as e:
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
            # ✅ Get user_id from session
            user_id = request.session.get("user_id")
            if not user_id:
                messages.error(request, "User not logged in.")
                return redirect("login")

            # ✅ Upload file to Supabase Storage
            file_name = f"{uuid.uuid4()}_{uploaded_file.name}"
            upload_res = supabase.storage.from_(settings.SUPABASE_BUCKET).upload(
                file_name, uploaded_file.read()
            )

            # ✅ Check for upload errors
            if isinstance(upload_res, dict) and upload_res.get("error"):
                messages.error(request, f"Upload failed: {upload_res['error']['message']}")
                return redirect("addfiles")

            # ✅ Get public file URL
            public_url = supabase.storage.from_(settings.SUPABASE_BUCKET).get_public_url(file_name)

            # ✅ Detect file type automatically using extension
            file_ext = os.path.splitext(uploaded_file.name)[1].lower()  # e.g. ".pdf"
            if file_ext.startswith("."):
                file_ext = file_ext[1:]  # remove dot → "pdf", "docx", "txt"

            # ✅ Insert clean data to Supabase
            resource_data = {
                "id": str(uuid.uuid4()),
                "title": title,
                "subject": subject,
                "grade": grade,
                "description": description,
                "file_path": public_url,
                "file_size": f"{round(uploaded_file.size / 1024, 2)} KB",
                "file_type": file_ext,  # ✅ correct readable type
                "date_added": timezone.now().isoformat(),
                "user_id": user_id,
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



def delete_file(request, id):
    if request.method == "POST":
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "You must log in to delete a file.")
            return redirect("login")

        try:
            # ✅ Get file record from Supabase
            file_res = supabase.table("resources").select("*").eq("id", id).execute()
            if not file_res.data:
                messages.error(request, "File not found.")
                return redirect("overview")

            file_data = file_res.data[0]

            # ✅ Make sure the user owns this file
            if file_data.get("user_id") != user_id:
                messages.error(request, "You can only delete your own files.")
                return redirect("overview")

            # ✅ Extract file name from file_path (to delete from storage)
            file_url = file_data.get("file_path", "")
            file_name = file_url.split("/")[-1] if "/" in file_url else file_url

            # ✅ Delete from Supabase Storage
            supabase.storage.from_(settings.SUPABASE_BUCKET).remove([f"user_uploads/{user_id}/{file_name}"])

            # ✅ Delete from Supabase Table
            supabase.table("resources").delete().eq("id", id).execute()

            messages.success(request, "File deleted successfully!")
            return redirect("overview")

        except Exception as e:
            messages.error(request, f"Error deleting file: {e}")
            return redirect("overview")

    messages.error(request, "Invalid request method.")
    return redirect("overview")



def favorites(request):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Please log in to view favorites.")
            return redirect("login")

        response = (
            supabase.table("resources")
            .select("*")
            .eq("user_id", str(user_id))
            .eq("is_favorite", True)
            .order("date_added", desc=True)
            .execute()
        )

        favorites = response.data or []

        # ✅ Convert Supabase string timestamps into formatted time
        for file in favorites:
            date_str = file.get("date_added")

            if date_str:
                try:
                    dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f%z")
                    file["formatted_date"] = dt.strftime("%b %d %Y, %I:%M %p")
                except:
                    file["formatted_date"] = "Unknown"
            else:
                file["formatted_date"] = "Unknown"

        return render(request, "favorites.html", {"favorites": favorites})

    except Exception as e:
        messages.error(request, f"Error loading favorites: {e}")
        return redirect("overview")



def profiled(request):
    return render(request, 'profiled.html')

def about(request):
    return render(request, 'about.html')


def logout_view(request):
    """
    Custom logout that supports 'Remember Me':
    - Removes only authentication data
    - Keeps session cookie alive if 'remember me' was selected
    - Does NOT flush entire session (important!)
    """

    # ❌ Do NOT use logout(request) because it clears the whole session
    # logout(request)

    # 🔥 Instead, manually remove auth-related session keys
    auth_keys = ["_auth_user_id", "_auth_user_backend", "_auth_user_hash"]

    for key in auth_keys:
        if key in request.session:
            del request.session[key]

    # Keep other session values like session expiry (remember me)
    # DO NOT delete request.session['session_key']

    # Optional: clear custom Supabase-related keys
    request.session.pop("access_token", None)

    messages.success(request, "You have been logged out.")

    return redirect("login")

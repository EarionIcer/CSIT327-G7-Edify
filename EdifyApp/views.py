
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
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import get_user_model
from datetime import datetime
import uuid
from EdifyProject.settings import supabase
from django.db.models import Q 



from django.contrib.auth import login as django_login
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect
from django.contrib import messages

import os
import uuid
import requests # ✅ Needed for download_file
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login, authenticate, get_user_model
from django.contrib.auth.decorators import user_passes_test
from django.http import JsonResponse, HttpResponse, Http404
from django.conf import settings
from django.utils import timezone
from django.db.models import Q
from django.utils.timesince import timesince # ✅ Needed for overview
from django.utils.timezone import now # ✅ Needed for overview
from datetime import datetime # ✅ Needed for overview
from supabase import create_client, Client




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
import re
import os
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login, authenticate, get_user_model
from django.contrib.auth.decorators import user_passes_test
from django.conf import settings
from supabase import create_client, Client



CustomUser = get_user_model()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY") 
supabase: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


# API for the upload files

# --- UPLOADS (My Files) ---
def uploads(request):
    user_id = request.session.get("user_id")
    if not user_id:
        return redirect("login")

    str_user_id = str(user_id)
    query = request.GET.get('q', '').strip()
    subject_filter = request.GET.get('subject', 'All')

    try:
        db_query = supabase.table('resources').select('*').eq('user_id', str_user_id).order('date_added', desc=True)

        if query:
            db_query = db_query.ilike('title', f'%{query}%')
        
        if subject_filter != 'All':
            db_query = db_query.eq('subject', subject_filter)

        response = db_query.execute()
        resources = response.data if hasattr(response, 'data') else response

        # ✅ NEW: Check which files are favorited by the user
        favorited_ids = []
        try:
            fav_res = supabase.table('favorites').select('file_id').eq('user_id', str_user_id).execute()
            fav_data = fav_res.data if hasattr(fav_res, 'data') else fav_res
            favorited_ids = [item['file_id'] for item in fav_data]
        except Exception as e:
            print(f"Fav fetch error: {e}")

        # Mark files as favorited
        for file in resources:
            file['is_favorite'] = file['id'] in favorited_ids

    except Exception as e:
        print(f"Error fetching uploads: {e}")
        resources = []

    subjects = sorted(list(set(f['subject'] for f in resources if f.get('subject'))))

    return render(request, 'uploads.html', {
        'resources': resources,
        'query': query,
        'selected_subject': subject_filter,
        'subjects': subjects
    })



#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


def edit_file(request, file_id):
    user_id = request.session.get("user_id")
    if not user_id:
        return redirect("login")

    # GET
    if request.method == "GET":
        try:
            resp = supabase.table("resources").select("*").eq("id", str(file_id)).single().execute()
            resource = resp.data if hasattr(resp, 'data') else resp
            return render(request, "edit_file.html", {"file": resource})
        except:
            return redirect("uploads")

    # POST
    if request.method == "POST":
        title = request.POST.get("title").strip()
        subject = request.POST.get("subject", "").strip()
        grade = request.POST.get("grade", "").strip()
        description = request.POST.get("description", "").strip()
        visibility = request.POST.get("visibility", "private")
        uploaded_file = request.FILES.get("file")

        update_data = {
            "title": title,
            "subject": subject,
            "grade": grade,
            "description": description,
            "visibility": visibility,
            "date_change": timezone.now().isoformat() # ✅ Update modification time
        }

        if visibility == 'public':
            update_data['status'] = 'pending'
        else:
            update_data['status'] = 'approved'

        try:
            if uploaded_file:
                # (File replacement logic...)
                file_name = f"{uuid.uuid4()}_{uploaded_file.name.replace(' ', '_')}"
                supabase.storage.from_(settings.SUPABASE_BUCKET).upload(
                    file_name, uploaded_file.read(), {"content-type": uploaded_file.content_type}
                )
                public_url_res = supabase.storage.from_(settings.SUPABASE_BUCKET).get_public_url(file_name)
                public_url = public_url_res if isinstance(public_url_res, str) else public_url_res.get('publicURL', '')
                
                update_data.update({
                    "file_path": public_url,
                    "file_type": os.path.splitext(uploaded_file.name)[1].replace('.', '').lower(),
                    "file_size": f"{round(uploaded_file.size / 1024, 2)} KB",
                })

            supabase.table("resources").update(update_data).eq("id", str(file_id)).execute()
            messages.success(request, "File updated.")
            return redirect("uploads")

        except Exception as e:
            messages.error(request, f"Error: {e}")
            return redirect("edit_file", file_id=file_id)


#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


def forgot_password_view(request):
    # Default to Step 1 (Email input)
    step = 1 

    if request.method == "POST":
        action = request.POST.get("action")

        # ==========================================
        # STEP 1: CHECK EMAIL
        # ==========================================
        if action == "check_email":
            email = request.POST.get("email", "").strip().lower()
            
            if not email:
                messages.error(request, "⚠️ Please enter your email address.")
            else:
                user = CustomUser.objects.filter(email=email).first()
                if user:
                    # ✅ Store email in session to prevent tampering in step 2
                    request.session['reset_email'] = email
                    messages.success(request, "✅ Email verified! Please create a new password.")
                    step = 2 # Move to next step
                else:
                    messages.error(request, "❌ This email is not registered.")

        # ==========================================
        # STEP 2: RESET PASSWORD
        # ==========================================
        elif action == "reset_password":
            # Get email from session (Secure)
            email = request.session.get('reset_email')
            new_password = request.POST.get("password", "")
            confirm_password = request.POST.get("confirm_password", "")

            # 1. Security Check
            if not email:
                messages.error(request, "⚠️ Session expired. Please start over.")
                return redirect("forgot_password")

            # 2. Validation
            if new_password != confirm_password:
                messages.error(request, "❌ Passwords do not match.")
                step = 2 # Stay on step 2
            
            # 3. Password Complexity Check
            elif len(new_password) < 8:
                messages.error(request, "⚠️ Password must be at least 8 characters.")
                step = 2
            elif not re.search(r"[A-Z]", new_password):
                messages.error(request, "⚠️ Password must contain an uppercase letter.")
                step = 2
            elif not re.search(r"[0-9]", new_password):
                messages.error(request, "⚠️ Password must contain a number.")
            elif not re.search(r"[!@#$%^&*]", new_password):
                messages.error(request, "⚠️ Password must contain a special character.")
                step = 2
            
            else:
                # 4. Save to Database
                user = CustomUser.objects.filter(email=email).first()
                if user:
                    user.password = make_password(new_password)
                    user.save()
                    
                    # Clean up session
                    del request.session['reset_email']
                    
                    messages.success(request, "🎉 Password reset successful! You can now login.")
                    return redirect("login")
                else:
                    messages.error(request, "❌ User not found.")

    # Render the page with the current step context
    return render(request, "forgot_password.html", {"step": step})


#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


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

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------



def toggle_favorite(request, id):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Please log in first.")
            return redirect("login")

        # Check if already favorited
        # Need to cast ID to string 
        str_user_id = str(user_id)
        str_file_id = str(id)

        existing = supabase.table('favorites').select('*').eq('user_id', str_user_id).eq('file_id', str_file_id).execute()
        data = existing.data if hasattr(existing, 'data') else existing

        if data:
            # Remove
            supabase.table('favorites').delete().eq('user_id', str_user_id).eq('file_id', str_file_id).execute()
            messages.info(request, "Removed from favorites.")
        else:
            # Add
            supabase.table('favorites').insert({'user_id': str_user_id, 'file_id': str_file_id}).execute()
            messages.success(request, "Added to favorites ⭐")

        # Redirect back to previous page (Public or Uploads or Favorites)
        return redirect(request.META.get('HTTP_REFERER', 'uploads'))

    except Exception as e:
        messages.error(request, f"Error updating favorite: {e}")
        return redirect("uploads")
    
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------    


# --- REGISTER VIEW (Updated with Backend Validation) ---
def register(request):
    # ✅ Initialize context to keep values if registration fails
    context = {} 

    if request.method == "POST":
        # ✅ Get data
        first_name = request.POST.get("first_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        email = request.POST.get("email", "").strip().lower()
        password = request.POST.get("password", "")
        confirm_password = request.POST.get("confirm_password", "")

        # ✅ Save input to context so user doesn't have to re-type everything on error
        context = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email
        }

        # --- 1️⃣ Basic validation ---
        if not all([first_name, last_name, email, password, confirm_password]):
            messages.error(request, "⚠️ Please fill out all fields.")
            return render(request, "register.html", context)

        if password != confirm_password:
            messages.error(request, "❌ Passwords do not match.")
            return render(request, "register.html", context)

        # --- 2️⃣ Backend Password Complexity Check ---
        if len(password) < 8:
            messages.error(request, "⚠️ Password must be at least 8 characters.")
            return render(request, "register.html", context)
        
        if not re.search(r"[A-Z]", password):
            messages.error(request, "⚠️ Password must contain at least one uppercase letter.")
            return render(request, "register.html", context)

        if not re.search(r"[a-z]", password):
            messages.error(request, "⚠️ Password must contain at least one lowercase letter.")
            return render(request, "register.html", context)

        if not re.search(r"[0-9]", password):
            messages.error(request, "⚠️ Password must contain at least one number.")
            return render(request, "register.html", context)

        if not re.search(r"[!@#$%^&*]", password):
            messages.error(request, "⚠️ Password must contain at least one special character (!@#$%^&*).")
            return render(request, "register.html", context)

        # --- 3️⃣ Check for duplicate email ---
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "📧 Email already exists.")
            return render(request, "register.html", context)

        try:
            # --- 4️⃣ Create local Django user ---
            hashed_pw = make_password(password)
            
            # ✅ Create the user
            local_user = CustomUser.objects.create(
                email=email,
                username=email, # Using email as username
                first_name=first_name,
                last_name=last_name,
                password=hashed_pw,
            )

            # --- 5️⃣ Log the user in ---
            login(request, local_user)

            # ✅ Store Django’s integer ID in session (Cast to string for Supabase compatibility)
            request.session["user_id"] = str(local_user.id)
            request.session["user_email"] = local_user.email

            messages.success(request, f"🎉 Welcome, {first_name}! Your account has been created.")
            return redirect("overview")

        except Exception as e:
            print("❌ Registration error:", e)
            messages.error(request, "🚨 Registration failed. Please try again later.")
            return render(request, "register.html", context)

    return render(request, "register.html", context)

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------






# ... imports ...

def public_files(request):
    query = request.GET.get('q', '').strip()
    subject_filter = request.GET.get('subject', 'All')

    try:
        # 1. Base Query
        db_query = supabase.table('resources')\
            .select('*')\
            .eq('visibility', 'public')\
            .eq('status', 'approved')\
            .order('date_added', desc=True)

        if query:
            db_query = db_query.or_(f"title.ilike.%{query}%,subject.ilike.%{query}%,grade.ilike.%{query}%")

        if subject_filter != 'All':
            db_query = db_query.eq('subject', subject_filter)

        response = db_query.execute()
        public_files = response.data if hasattr(response, 'data') else response

        # 2. Get User IDs
        user_ids = [f['user_id'] for f in public_files if 'user_id' in f]
        
        # 3. Map User Names
        users_map = {}
        if user_ids:
            try:
                django_users = CustomUser.objects.filter(id__in=user_ids)
                for u in django_users:
                    users_map[str(u.id)] = f"{u.first_name} {u.last_name}".strip() or u.email
            except ValueError:
                pass

        # 4. Check Favorites
        current_user_id = str(request.session.get('user_id', ''))
        favorited_ids = []
        if current_user_id:
            try:
                fav_res = supabase.table('favorites').select('file_id').eq('user_id', current_user_id).execute()
                fav_data = fav_res.data if hasattr(fav_res, 'data') else fav_res
                favorited_ids = [item['file_id'] for item in fav_data]
            except:
                pass

        for file in public_files:
            file['is_favorite'] = file['id'] in favorited_ids
            
            f_uid = str(file.get('user_id'))
            if f_uid == current_user_id:
                file['author_name'] = "You"
            else:
                file['author_name'] = users_map.get(f_uid, "Unknown User")

    except Exception as e:
        print(f"Search error: {e}")
        public_files = []

    subjects = sorted(list(set(f['subject'] for f in public_files if f.get('subject'))))

    return render(request, 'public.html', {
        'results': public_files, 
        'query': query,
        'selected_subject': subject_filter,
        'subjects': subjects
    })


#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------

# --- 2. LOGIN VIEW (Updated for Admin Redirect) ---
def login_view(request):
    # If user is already logged in, redirect them
    if request.user.is_authenticated:
        if request.user.is_superuser:
            return redirect('admin_dashboard')
        return redirect('overview')

    if request.method == "POST":
        email = request.POST.get("emailAd") # Make sure this matches your HTML input name
        password = request.POST.get("password")
        
        user = authenticate(request, email=email, password=password)
        
        if user is not None:
            login(request, user)
            request.session['user_id'] = user.id 

            # ✅ CHECK ADMIN STATUS
            if user.is_superuser:
                messages.success(request, f"Welcome Admin, {user.first_name}!")
                return redirect('admin_dashboard')
            else:
                messages.success(request, f"Welcome back, {user.first_name}!")
                return redirect('overview')
        else:
            messages.error(request, "Invalid credentials.")
            
    return render(request, 'login.html')


#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
   


# --- 3. ADMIN HELPER ---
def is_superuser(user):
    return user.is_authenticated and user.is_superuser

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------



# --- 4. ADMIN DASHBOARD VIEW ---
@user_passes_test(is_superuser, login_url='login')
def admin_dashboard(request):
    # (Your existing admin dashboard logic...)
    # Just ensure you use the updated imports above
    
    # Fetch Pending
    try:
        pending_res = supabase.table('resources').select('*').eq('status', 'pending').eq('visibility', 'public').execute()
        pending_files = pending_res.data if hasattr(pending_res, 'data') else pending_res
    except:
        pending_files = []

    total_users = CustomUser.objects.count()
    
    try:
        all_res = supabase.table('resources').select('visibility', count='exact').execute()
        all_data = all_res.data if hasattr(all_res, 'data') else all_res
        public_count = sum(1 for f in all_data if f.get('visibility') == 'public')
        private_count = len(all_data) - public_count
    except:
        public_count = 0
        private_count = 0

    users = CustomUser.objects.all().order_by('-date_joined')

    context = {
        'pending_files': pending_files,
        'users': users,
        'total_users': total_users,
        'public_files': public_count,
        'private_files': private_count,
    }
    return render(request, 'admin_dashboard.html', context)

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------



# --- 5. APPROVE FILE ACTION ---
# ... include approve_file, delete_file_admin, admin_files, admin_users from previous steps ...
@user_passes_test(is_superuser, login_url='login')
def approve_file(request, file_id):
    if request.method == "POST":
        try:
            supabase.table('resources').update({'status': 'approved'}).eq('id', file_id).execute()
            messages.success(request, "✅ File approved.")
        except Exception as e:
            messages.error(request, f"Error: {e}")
    return redirect('admin_dashboard') # or admin_files
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------



# --- 6. DELETE FILE ACTION (Admin) ---
@user_passes_test(is_superuser, login_url='login')
def delete_file_admin(request, file_id):
    if request.method == "POST":
        try:
            # Delete from DB (Rejection)
            supabase.table('resources').delete().eq('id', file_id).execute()
            messages.success(request, "❌ File rejected and deleted.")
        except Exception as e:
            messages.error(request, f"Error deleting file: {e}")
            
    return redirect('admin_dashboard')

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------



# --- 7. DELETE USER ACTION ---
@user_passes_test(is_superuser, login_url='login')
def delete_user(request, user_id):
    if request.method == "POST":
        user_to_delete = get_object_or_404(CustomUser, id=user_id)
        
        # Security: Prevent deleting admins
        if not user_to_delete.is_superuser:
            user_to_delete.delete()
            messages.success(request, "User deleted successfully.")
        else:
            messages.error(request, "⚠️ You cannot delete an administrator account.")
            
    return redirect('admin_dashboard')

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------



def download_file(request, file_id):
    user_id = request.session.get("user_id")
    if not user_id:
        return redirect("login")

    try:
        response = supabase.table("resources").select("*").eq("id", str(file_id)).single().execute()
        file_data = response.data if hasattr(response, 'data') else response

        if not file_data:
            raise Http404("File not found.")

        # Optional: Ensure ownership or public access logic here
        # if file_data["user_id"] != str(user_id) and file_data['visibility'] != 'public':
        #    return HttpResponse("Unauthorized access.", status=403)

        file_url = file_data["file_path"]
        file_name = file_data["title"] or "downloaded_file"
        file_type = file_data.get("file_type", "bin")

        # Stream file from Supabase
        file_response = requests.get(file_url)
        if file_response.status_code != 200:
            return HttpResponse("Error downloading file from Supabase.", status=500)

        response = HttpResponse(
            file_response.content,
            content_type="application/octet-stream"
        )
        response["Content-Disposition"] = f'attachment; filename="{file_name}.{file_type}"'
        return response

    except Exception as e:
        print("Download error:", str(e))
        raise Http404("Error downloading file.")
    

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------    


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
        return redirect("public")

    file = file_data.data[0]
    return render(request, "file_detail.html", {"file": file})

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------



def navbar(request):
    user = request.session.get("user")
    if not user:
        return redirect("login")

    success_message = request.session.pop("success_message", None)
    return render(request, "navbar.html", {"success": success_message})


#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


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
    


#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


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
    
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------    

    
# add files
def add_files(request):
    if request.method == "POST":
        title = request.POST.get("title").strip()
        subject = request.POST.get("subject", "").strip() # Default empty if not in form
        grade = request.POST.get("grade", "").strip()
        description = request.POST.get("description", "").strip()
        uploaded_file = request.FILES.get("file")
        visibility = request.POST.get("visibility", "private")

        if not uploaded_file or not title:
            messages.error(request, "Please provide a title and file.")
            return redirect("addfiles")

        try:
            user_id = request.session.get("user_id")
            if not user_id:
                return redirect("login")

            # Upload to Storage
            file_name = f"{uuid.uuid4()}_{uploaded_file.name.replace(' ', '_')}"
            supabase.storage.from_(settings.SUPABASE_BUCKET).upload(
                file_name, uploaded_file.read(), {"content-type": uploaded_file.content_type}
            )
            
            public_url_res = supabase.storage.from_(settings.SUPABASE_BUCKET).get_public_url(file_name)
            public_url = public_url_res if isinstance(public_url_res, str) else public_url_res.get('publicURL', '')

            filename, file_extension = os.path.splitext(uploaded_file.name)
            file_type = file_extension.replace('.', '').lower()

            status = 'pending' if visibility == 'public' else 'approved'

            resource_data = {
                "title": title,
                "subject": subject,
                "grade": grade,
                "description": description,
                "file_path": public_url,
                "file_size": f"{round(uploaded_file.size / 1024, 2)} KB",
                "file_type": file_type,
                "date_added": timezone.now().isoformat(),
                "user_id": str(user_id), # ✅ Ensure string
                "visibility": visibility,
                "status": status,
                # "is_favorite": False # Optional, if you really want it in the table
            }

            supabase.table("resources").insert(resource_data).execute()

            if visibility == 'public':
                messages.success(request, "✅ Uploaded! Waiting for Admin approval.")
            else:
                messages.success(request, "✅ Uploaded to private files.")
            
            return redirect("uploads")

        except Exception as e:
            messages.error(request, f"Upload error: {e}")
            return redirect("addfiles")

    return render(request, "addfiles.html")


#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------



def view_file(request, pk):
    file = get_object_or_404(UploadedFile, pk=pk)
    return render(request, 'view_file.html', {'file': file})

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------



def delete_file(request, id):
    if request.method == "POST":
        user_id = request.session.get("user_id")
        if not user_id:
            return redirect("login")

        try:
            file_res = supabase.table("resources").select("*").eq("id", id).execute()
            file_data = file_res.data[0] if file_res.data else None

            if file_data and str(file_data.get("user_id")) == str(user_id):
                # Note: You might need to parse file path to get storage key if needed
                # supabase.storage...remove(...) 
                supabase.table("resources").delete().eq("id", id).execute()
                messages.success(request, "File deleted successfully!")
            else:
                messages.error(request, "Unauthorized.")
                
        except Exception as e:
            messages.error(request, f"Error: {e}")
            
    return redirect("uploads")

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------



def favorites(request):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Please log in to view favorites.")
            return redirect("login")

        str_user_id = str(user_id)

        # 1. Get IDs of files this user has favorited from the 'favorites' table
        fav_res = supabase.table('favorites').select('file_id').eq('user_id', str_user_id).execute()
        fav_data = fav_res.data if hasattr(fav_res, 'data') else fav_res
        
        # Extract just the IDs: ['id1', 'id2', ...]
        fav_ids = [f['file_id'] for f in fav_data]

        favorites_list = []
        
        # 2. Fetch the actual file details from 'resources' if we have favorites
        if fav_ids:
            # Use .in_() to get all files that match the IDs
            res = supabase.table('resources').select('*').in_('id', fav_ids).order('date_added', desc=True).execute()
            favorites_list = res.data if hasattr(res, 'data') else res

            # 3. Your Date Formatting Logic & Flags
            for file in favorites_list:
                # Mark as favorite for the UI (Red heart)
                file['is_favorite'] = True
                
                # Your date logic
                date_str = file.get("date_added")
                if date_str:
                    try:
                        # Handling timezone 'Z' manually if needed, or let fromisoformat handle it
                        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                        file["formatted_date"] = dt.strftime("%b %d %Y, %I:%M %p")
                    except:
                        file["formatted_date"] = "Unknown"
                else:
                    file["formatted_date"] = "Unknown"

        return render(request, "favorites.html", {"favorites": favorites_list})

    except Exception as e:
        print(f"Fav Error: {e}")
        messages.error(request, f"Error loading favorites: {e}")
        return redirect("overview")
    

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------    



def profiled(request):
    return render(request, 'profiled.html')

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------

def about(request):
    return render(request, 'about.html')

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


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
    request.session.flush()

    return redirect("login")

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


@user_passes_test(is_superuser, login_url='login')
def admin_files(request):
    # (Your admin_files logic from previous steps)
    try:
        pending_res = supabase.table('resources').select('*').eq('status', 'pending').eq('visibility', 'public').execute()
        pending_files = pending_res.data if hasattr(pending_res, 'data') else pending_res
    except:
        pending_files = []

    query = request.GET.get('q', '').strip()
    try:
        db_query = supabase.table('resources').select('*').order('date_added', desc=True)
        if query:
            db_query = db_query.ilike('title', f'%{query}%')
        all_res = db_query.execute()
        all_files = all_res.data if hasattr(all_res, 'data') else all_res
    except:
        all_files = []

    return render(request, 'admin_files.html', {'pending_files': pending_files, 'all_files': all_files, 'query': query})



#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


@user_passes_test(is_superuser, login_url='login')
def admin_users(request):
    query = request.GET.get('q', '').strip()
    users = CustomUser.objects.all().order_by('-date_joined')
    if query:
        users = users.filter(Q(first_name__icontains=query) | Q(last_name__icontains=query) | Q(email__icontains=query))
    return render(request, 'admin_users.html', {'users': users, 'query': query})

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


# --- TOGGLE VISIBILITY ---
def toggle_visibility(request, file_id):
    user_id = request.session.get("user_id")
    if not user_id or request.method != "POST":
        return redirect("uploads")

    try:
        current_res = supabase.table('resources').select('visibility').eq('id', file_id).single().execute()
        current_data = current_res.data if hasattr(current_res, 'data') else current_res
        
        new_vis = 'public' if current_data['visibility'] == 'private' else 'private'
        new_status = 'pending' if new_vis == 'public' else 'approved'

        supabase.table('resources').update({
            'visibility': new_vis,
            'status': new_status,
            'date_change': timezone.now().isoformat() # ✅ Track change
        }).eq('id', file_id).execute()

        if new_vis == 'public':
            messages.success(request, "File is now Public (Pending Approval).")
        else:
            messages.success(request, "File is now Private.")

    except Exception as e:
        messages.error(request, f"Error: {e}")

    return redirect('uploads')

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------

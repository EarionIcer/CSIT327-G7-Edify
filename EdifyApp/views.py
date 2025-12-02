# ==========================================
# 1. STANDARD LIBRARY IMPORTS
# ==========================================
import os                       # Operating system interfaces (file paths, env vars)
import re                       # Regular expressions (used for password validation)
import uuid                     # Generate unique IDs (UUIDs) for files
import logging                  # System logging
from datetime import datetime   # Date and time manipulation
from sqlite3 import IntegrityError # Handle database integrity errors

# ==========================================
# 2. THIRD-PARTY LIBRARIES
# ==========================================
import requests                 # Send HTTP requests (used for file downloading)
from supabase import create_client, Client  # Interface for Supabase database

# ==========================================
# 3. DJANGO CORE IMPORTS
# ==========================================
from django.conf import settings                # Access project settings (API keys, etc.)
from django.shortcuts import render, redirect, get_object_or_404 # View rendering & redirection
from django.http import JsonResponse, HttpResponse, Http404      # HTTP response types
from django.contrib import messages             # Flash messages (success/error alerts)
from django.db.models import Q                  # Complex database queries (OR lookups)
from django.db import ProgrammingError          # Handle database errors
from django.core.mail import send_mail          # Send emails
from django.utils import timezone               # Timezone utilities
from django.utils.timezone import now, localtime, make_aware # Time helpers
from django.utils.timesince import timesince    # Relative time formatting ("5 mins ago")
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode # Encoding for tokens
from django.utils.encoding import force_bytes, force_str # String encoding helpers
from django.contrib.humanize.templatetags.humanize import naturaltime # Human-readable time tags

# ==========================================
# 4. DJANGO AUTHENTICATION & SECURITY
# ==========================================
from django.contrib.auth import login, logout, authenticate, get_user_model # Auth functions
from django.contrib.auth.decorators import login_required, user_passes_test # View protection decorators
from django.contrib.auth.hashers import make_password, check_password       # Password security
from django.contrib.auth.tokens import default_token_generator              # Generate secure tokens
from django.views.decorators.csrf import csrf_exempt   # Exempt views from CSRF checks (use sparingly)
from django.views.decorators.cache import never_cache  # Prevent browser caching (security)

# ==========================================
# 5. LOCAL APP IMPORTS
# ==========================================
from .models import CustomUser, Resource, UploadedFile  # Your database models
from .forms import UploadForm   # Django forms

# ==========================================
# 6. INITIALIZATION
# ==========================================
# Get the active User model
CustomUser = get_user_model()

# Initialize Supabase Client
# Uses credentials from your settings.py
supabase: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)




#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------



# --- UPLOADS (My Files) ---
# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
def uploads(request):
    """
    View to display the current user's uploaded files.
    Handles authentication, searching, filtering by subject, and favorite status.
    """
    # 1. Security Check: Verify the user is logged in via session
    user_id = request.session.get("user_id")
    if not user_id:
        return redirect("login")

    str_user_id = str(user_id)
    
    # 2. Retrieve Search & Filter Parameters from the URL (GET request)
    query = request.GET.get('q', '').strip()
    subject_filter = request.GET.get('subject', 'All')

    try:
        # 3. Build the Database Query
        # Select all resources belonging to this user, ordered by newest first
        db_query = supabase.table('resources').select('*').eq('user_id', str_user_id).order('date_added', desc=True)

        # 4. Apply Search Logic (if user typed a search term)
        # 'ilike' performs a case-insensitive search on the title
        if query:
            db_query = db_query.ilike('title', f'%{query}%')
        
        # 5. Apply Subject Filter (if user selected a subject)
        if subject_filter != 'All':
            db_query = db_query.eq('subject', subject_filter)

        # 6. Execute Query
        # Limit results to 50 to prevent browser lag when rendering many items
        response = db_query.limit(50).execute()
        resources = response.data if hasattr(response, 'data') else response

        # 7. Handle Favorites Status
        # ✅ INSERT FAVORITES FIX RIGHT HERE ⬇⬇⬇
        # Fetch list of ALL file IDs that this user has favorited
        fav_res = supabase.table("favorites").select("file_id").eq("user_id", str_user_id).execute()
        fav_data = fav_res.data if hasattr(fav_res, "data") else fav_res

        # Convert to a Set for faster lookup (O(1) complexity)
        favorited_ids = set(str(item["file_id"]) for item in fav_data)

        # Iterate through the fetched resources and mark them as favorited if they exist in the set
        for file in resources:
            file_id = str(file.get("id"))
            file["is_favorite"] = file_id in favorited_ids
        # ✅ END FIX ⬆⬆⬆

    except Exception as e:
        # Log errors to console for debugging, return empty list to prevent crash
        print(f"Error fetching uploads: {e}")
        resources = []

    # 8. Extract Unique Subjects for the Filter Dropdown
    # Uses a set comprehension to get unique values, then sorts them alphabetically
    subjects = sorted(list(set(f['subject'] for f in resources if f.get('subject'))))

    # 9. Render the Template
    # Pass the processed data (resources, filters, subjects) to the HTML
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


# --- EDIT FILE (Protected) ---
# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
def edit_file(request, file_id):
    """
    View to handle editing of an existing resource.
    Supports fetching current data (GET) and updating metadata/file (POST).
    """
    # 1. Security Check: Ensure user is logged in
    user_id = request.session.get("user_id")
    if not user_id:
        return redirect("login")

    # GET: Render the edit form pre-filled with current file data
    if request.method == "GET":
        try:
            # Fetch specific file by ID from Supabase
            resp = supabase.table("resources").select("*").eq("id", str(file_id)).single().execute()
            resource = resp.data if hasattr(resp, 'data') else resp
            # Render template with file context
            return render(request, "edit_file.html", {"file": resource})
        except:
            # Redirect if file not found or error occurs
            return redirect("uploads")

    # POST: Handle form submission to update the file
    if request.method == "POST":
        # 2. Retrieve form data
        title = request.POST.get("title").strip()
        subject = request.POST.get("subject", "").strip()
        grade = request.POST.get("grade", "").strip()
        description = request.POST.get("description", "").strip()
        visibility = request.POST.get("visibility", "private")
        uploaded_file = request.FILES.get("file") # Optional new file

        # 3. Prepare update payload for Supabase
        update_data = {
            "title": title,
            "subject": subject,
            "grade": grade,
            "description": description,
            "visibility": visibility,
            "date_changed": timezone.now().isoformat() # ✅ Update modification time timestamp
        }

        # 4. Apply Business Logic for Status
        # If user makes file Public -> It requires Admin approval (Pending)
        # If user makes file Private -> It is auto-approved (Safe)
        if visibility == 'public':
            update_data['status'] = 'pending'
        else:
            update_data['status'] = 'approved'

        try:
            # 5. Handle File Replacement (If a new file is uploaded)
            if uploaded_file:
                # Generate unique filename to prevent overwrites
                file_name = f"{uuid.uuid4()}_{uploaded_file.name.replace(' ', '_')}"
                
                # Upload new file to Supabase Storage
                supabase.storage.from_(settings.SUPABASE_BUCKET).upload(
                    file_name, uploaded_file.read(), {"content-type": uploaded_file.content_type}
                )
                
                # Get public URL for the new file
                public_url_res = supabase.storage.from_(settings.SUPABASE_BUCKET).get_public_url(file_name)
                public_url = public_url_res if isinstance(public_url_res, str) else public_url_res.get('publicURL', '')
                
                # Update file-specific metadata in the payload
                update_data.update({
                    "file_path": public_url,
                    "file_type": os.path.splitext(uploaded_file.name)[1].replace('.', '').lower(),
                    "file_size": f"{round(uploaded_file.size / 1024, 2)} KB",
                })

            # 6. Execute Update in Database
            supabase.table("resources").update(update_data).eq("id", str(file_id)).execute()
            
            # Success feedback
            messages.success(request, "File updated.")
            return redirect("uploads")

        except Exception as e:
            # Error handling
            messages.error(request, f"Error: {e}")
            return redirect("edit_file", file_id=file_id)


#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------

# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
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

# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
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


# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
def toggle_favorite(request, id):
    """
    Toggles the favorite status of a file.
    Returns JSON so JavaScript can update the heart icon without reloading.
    """
    if request.method != "POST":
        return JsonResponse({"status": "error"}, status=400)

    user_id = request.session.get("user_id")
    if not user_id:
        return JsonResponse({"status": "unauthenticated"}, status=401)

    try:
        user_id = int(user_id)
        file_id = str(id)

        # Check if favorite exists
        res = supabase.table("favorites") \
            .select("id") \
            .eq("user_id", user_id) \
            .eq("file_id", file_id) \
            .execute()

        data = res.data or []

        # TOGGLE
        if data:
            supabase.table("favorites").delete() \
                .eq("user_id", user_id) \
                .eq("file_id", file_id) \
                .execute()

            new_state = False
            message = "Removed from favorites."

        else:
            supabase.table("favorites").insert({
                "user_id": user_id,
                "file_id": file_id
            }).execute()

            new_state = True
            message = "Added to favorites ⭐"

        # Send updated count
        count_res = supabase.table("favorites").select("id").eq("user_id", user_id).execute()
        fav_count = len(count_res.data or [])

        return JsonResponse({
            "status": "success",
            "is_favorite": new_state,
            "favorites_count": fav_count,
            "message": message  # ✅ THIS ENABLES TOAST
        })

    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------    

# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
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


# --- PUBLIC FILES (Paginated) ---
# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
def public_files(request):
    query = request.GET.get('q', '').strip()
    subject_filter = request.GET.get('subject', 'All')

    # ✅ 1. Pagination Setup
    page = int(request.GET.get('page', 1))
    per_page = 12  # 12 cards looks good in a grid layout
    
    start = (page - 1) * per_page
    end = start + per_page - 1

    try:
        # Base Query (Count exact for pagination buttons)
        db_query = supabase.table('resources').select('*', count='exact').eq('visibility', 'public').eq('status', 'approved').order('date_added', desc=True)

        if query:
            db_query = db_query.or_(f"title.ilike.%{query}%,subject.ilike.%{query}%,grade.ilike.%{query}%")

        if subject_filter != 'All':
            db_query = db_query.eq('subject', subject_filter)

        # ✅ 2. Fetch Range (Only 12 items)
        response = db_query.range(start, end).execute()
        public_files = response.data if hasattr(response, 'data') else response
        total_count = response.count if hasattr(response, 'count') else len(public_files)

        # 3. Map Users (Only for these 12 items)
        user_ids = [f['user_id'] for f in public_files if 'user_id' in f]
        users_map = {}
        if user_ids:
            try:
                django_users = CustomUser.objects.filter(id__in=user_ids)
                for u in django_users:
                    users_map[str(u.id)] = f"{u.first_name} {u.last_name}".strip() or u.email
            except ValueError:
                pass

        # 4. Check Favorites (Only for these 12 items)
        current_user_id = str(request.session.get('user_id', ''))
        favorited_ids = []
        if current_user_id and public_files:
            try:
                # Optimized: Filter favs by specific file IDs on this page
                page_file_ids = [p['id'] for p in public_files]
                fav_res = supabase.table('favorites').select('file_id').eq('user_id', current_user_id).in_('file_id', page_file_ids).execute()
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
        total_count = 0

    # ✅ 5. Fetch Subjects (Separate lightweight query to populate filter)
    # We can't rely on 'public_files' list because it only has 12 items.
    try:
        subj_res = supabase.table('resources').select('subject').eq('visibility', 'public').eq('status', 'approved').execute()
        subj_data = subj_res.data if hasattr(subj_res, 'data') else subj_res
        subjects = sorted(list(set(f['subject'] for f in subj_data if f.get('subject'))))
    except:
        subjects = []

    # ✅ 6. Pagination Flags
    has_next = total_count > end + 1
    has_prev = page > 1

    return render(request, 'public.html', {
        'results': public_files, 
        'query': query,
        'selected_subject': subject_filter,
        'subjects': subjects,
        'page': page,
        'has_next': has_next,
        'has_prev': has_prev,
        'next_page': page + 1,
        'prev_page': page - 1,
        'total_count': total_count
    })


#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------

# --- 2. LOGIN VIEW (Updated for Admin Redirect) ---
# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
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
    # 1. Fetch Pending Files
    try:
        pending_res = supabase.table('resources').select('*').eq('status', 'pending').eq('visibility', 'public').limit(10).execute()
        pending_files = pending_res.data if hasattr(pending_res, 'data') else pending_res
    except:
        pending_files = []

    # ✅ NEW: Attach User Names to Pending Files
    user_ids = [f['user_id'] for f in pending_files if 'user_id' in f]
    users_map = {}
    
    if user_ids:
        try:
            # Fetch user details from Django DB
            django_users = CustomUser.objects.filter(id__in=user_ids)
            for u in django_users:
                full_name = f"{u.first_name} {u.last_name}".strip()
                users_map[str(u.id)] = full_name if full_name else u.email
        except ValueError:
            pass # Handle cases where IDs might not match types

    # Attach the name to each file object
    for file in pending_files:
        uid = str(file.get('user_id'))
        file['uploader_name'] = users_map.get(uid, "Unknown User")


    # 2. Fetch Stats (Keep existing logic)
    total_users = CustomUser.objects.count()
    
    try:
        all_res = supabase.table('resources').select('visibility').limit(1000).execute()
        all_data = all_res.data if hasattr(all_res, 'data') else all_res
        public_count = sum(1 for f in all_data if f.get('visibility') == 'public')
        private_count = len(all_data) - public_count
    except:
        public_count = 0
        private_count = 0

    users = CustomUser.objects.all().order_by('-date_joined')[:10]

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


# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
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

# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
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


# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
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

# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
def overview(request):
    try:
        # Supabase user_id from session
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Please log in to view your dashboard.")
            return redirect("login")

        str_user_id = str(user_id)

        # 1) Fetch user's resources
        resp = supabase.table("resources").select("*").eq("user_id", str_user_id).order("date_added", desc=True).limit(100).execute()
        resources = resp.data if hasattr(resp, "data") else (resp or [])

        # 2) Fetch this user's favorite file_ids (single query)
        fav_resp = supabase.table("favorites").select("file_id").eq("user_id", str_user_id).execute()
        fav_data = fav_resp.data if hasattr(fav_resp, "data") else (fav_resp or [])
        favorited_ids = {str(item["file_id"]) for item in fav_data}

        # 3) Annotate resources with is_favorite and compute favorites list
        for r in resources:
            r_id = str(r.get("id") or r.get("Id") or r.get("file_id") or "")
            r["is_favorite"] = r_id in favorited_ids

        # favorites list (full resource records for favorites)
        favorites = [r for r in resources if r.get("is_favorite")]

        # 4) Compute stats
        total_uploads = len(resources)
        favorites_count = len(favorited_ids)
        subjects = {r.get('subject') for r in resources if r.get('subject')}
        subjects_count = len(subjects)

        # 5) Compute total storage (safe parse)
        total_kb = 0.0
        for r in resources:
            fs = r.get('file_size')
            if not fs:
                continue
            # Accept "183.91 KB" or "1200" style; try flexible parsing
            try:
                # if includes units like "KB" or "MB", split and parse number
                parts = str(fs).split()
                num = float(parts[0])
                unit = parts[1].upper() if len(parts) > 1 else "KB"
                if unit.startswith("KB"):
                    total_kb += num
                elif unit.startswith("MB"):
                    total_kb += num * 1024
                elif unit.startswith("B"):
                    total_kb += num / 1024
                else:
                    # fallback assume KB
                    total_kb += num
            except Exception:
                continue

        total_storage = f"{total_kb / 1024:.2f} MB" if total_kb > 1024 else f"{total_kb:.2f} KB"

        # 6) Human readable time_ago
        for r in resources:
            date_str = r.get("date_added")
            if date_str:
                try:
                    # Supabase likely returns ISO string e.g. "2025-11-26T20:00:00Z"
                    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    r["time_ago"] = timesince(dt, now()).split(",")[0] + " ago"
                except Exception:
                    r["time_ago"] = ""
            else:
                r["time_ago"] = ""

        # 7) Recent uploads
        recent_uploads = sorted(resources, key=lambda x: x.get('date_added', ''), reverse=True)[:5]

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
        # Helpful debug information in development
        return render(request, "overview.html", {"error": str(e)})

    


#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


# for uploading files
# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
def uploads(request):
    try:
        # ✅ User session
        user_id = request.session.get("user_id")
        if not user_id:
            return redirect("login")
        str_user_id = str(user_id)

        # ✅ Connect Supabase
        supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

        # ✅ Fetch uploads
        response = (
            supabase.table("resources")
            .select("*")
            .eq("user_id", str_user_id)   # MAKE SURE THIS COLUMN EXISTS
            .execute()
        )

        resources = response.data or []

        # ✅ FETCH FAVORITES FOR HEART STATE
        fav_res = supabase.table("favorites").select("file_id").eq("user_id", str_user_id).execute()
        fav_data = fav_res.data or []
        favorited_ids = {str(item["file_id"]) for item in fav_data}

        # ✅ APPLY HEART STATE
        for r in resources:
            rid = str(r.get("id") or r.get("file_id") or "")
            r["is_favorite"] = rid in favorited_ids

        # ✅ SUBJECT FILTER
        subjects = sorted({r.get("subject") for r in resources if r.get("subject")})
        selected_subject = request.GET.get("subject", "All")

        if selected_subject != "All":
            resources = [r for r in resources if r.get("subject") == selected_subject]

        # ✅ SEARCH FILTER
        query = request.GET.get("q", "").strip()
        if query:
            resources = [
                r for r in resources
                if query.lower() in r.get("title", "").lower()
                or query.lower() in r.get("subject", "").lower()
                or query.lower() in r.get("grade", "").lower()
            ]

        # ✅ CONTEXT
        context = {
            "resources": resources,
            "subjects": subjects,
            "selected_subject": selected_subject,
            "query": query,
        }

        return render(request, "uploads.html", context)

    except Exception as e:
        print("UPLOAD ERROR:", e)
        return render(request, "uploads.html", {"error": str(e)})


    
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------    

 # --- ADD FILES (Protected) ---
# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
def add_files(request):
    """
    View to handle the uploading of new resources.
    
    HOW IT WORKS:
    1. Checks for POST request (Form submission).
    2. Validates that essential data (File, Title) exists.
    3. Uploads the physical file to Supabase Storage.
    4. Generates a public URL for the file.
    5. Saves the file metadata (Title, Grade, URL, etc.) to the Supabase Database.
    6. Sets the status automatically based on visibility (Public -> Pending).
    """
    
    # Check if the request is a form submission
    if request.method == "POST":
        # 1. Retrieve data from the HTML form
        title = request.POST.get("title").strip()
        # 'subject' is optional, default to empty string if missing
        subject = request.POST.get("subject", "").strip() 
        grade = request.POST.get("grade", "").strip()
        description = request.POST.get("description", "").strip()
        
        # 'request.FILES' holds the actual file data uploaded by the user
        uploaded_file = request.FILES.get("file")
        # Default to 'private' if the visibility toggle wasn't set
        visibility = request.POST.get("visibility", "private")

        # 2. Basic Validation: Ensure Title and File are present
        if not uploaded_file or not title:
            messages.error(request, "Please provide a title and file.")
            return redirect("addfiles")

        try:
            # 3. Authentication Check: Get the user ID from the session
            user_id = request.session.get("user_id")
            if not user_id:
                # If session expired or invalid, force login
                return redirect("login")

            # 4. File Naming Strategy
            # We use UUID to create a unique filename to prevent overwriting existing files with the same name.
            # e.g., "math.pdf" -> "550e8400-e29b..._math.pdf"
            file_name = f"{uuid.uuid4()}_{uploaded_file.name.replace(' ', '_')}"
            
            # 5. Upload to Cloud Storage (Supabase)
            # We read the file chunks directly from memory and send them to the 'uploads' bucket.
            supabase.storage.from_(settings.SUPABASE_BUCKET).upload(
                file_name, uploaded_file.read(), {"content-type": uploaded_file.content_type}
            )
            
            # 6. Generate Access Link
            # We retrieve the public URL so users can download/view the file later.
            public_url_res = supabase.storage.from_(settings.SUPABASE_BUCKET).get_public_url(file_name)
            # Handle different return formats of the Supabase library (string vs dict)
            public_url = public_url_res if isinstance(public_url_res, str) else public_url_res.get('publicURL', '')

            # 7. Extract File Metadata
            # Get the file extension (e.g., .pdf, .docx) for display purposes
            filename, file_extension = os.path.splitext(uploaded_file.name)
            file_type = file_extension.replace('.', '').lower()

            # 8. Apply Business Logic for Approval
            # If the user wants it Public, it must be 'pending' approval by an Admin.
            # If Private, it is automatically 'approved' for their own use.
            status = 'pending' if visibility == 'public' else 'approved'

            # 9. Prepare Database Payload
            resource_data = {
                "title": title,
                "subject": subject,
                "grade": grade,
                "description": description,
                "file_path": public_url,
                "file_size": f"{round(uploaded_file.size / 1024, 2)} KB", # Convert bytes to KB
                "file_type": file_type,
                "date_added": timezone.now().isoformat(),
                "user_id": str(user_id), # ✅ Ensure ID is stored as a string to match database schema
                "visibility": visibility,
                "status": status,
                # "is_favorite": False # Optional, if you really want it in the table
            }

            # 10. Execute Database Insert
            # Adds the metadata row to the 'resources' table
            supabase.table("resources").insert(resource_data).execute()

            # 11. User Feedback
            if visibility == 'public':
                messages.success(request, "✅ Uploaded! Waiting for Admin approval.")
            else:
                messages.success(request, "✅ Uploaded to private files.")
            
            # Redirect to the list of uploads on success
            return redirect("uploads")

        except Exception as e:
            # 12. Error Handling
            # If Storage or Database fails, log the error and notify the user
            messages.error(request, f"Upload error: {e}")
            return redirect("addfiles")

    # If GET request, simply render the upload form
    return render(request, "addfiles.html")


#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
def view_file(request, pk):
    file = get_object_or_404(UploadedFile, pk=pk)
    return render(request, 'view_file.html', {'file': file})

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
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


# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
def favorites(request):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Please log in to view favorites.")
            return redirect("login")

        user_id = int(user_id)

        # 1. Get IDs of files this user has favorited from the 'favorites' table
        fav_res = supabase.table('favorites').select('*').eq('user_id', user_id).execute()
        fav_data = fav_res.data if hasattr(fav_res, 'data') else fav_res
        
        # Extract just the IDs: ['id1', 'id2', ...]
        fav_ids = [f['file_id'] for f in fav_data]

        favorites_list = []
        
        # 2. Fetch the favorites with timestamps and join with file details manually
        if fav_data:
            # Create a mapping: file_id -> date_favorited
            fav_map = {f["file_id"]: f.get("created_at") for f in fav_data}

            # Fetch the actual files
            res = supabase.table("resources").select("*").in_("id", list(fav_map.keys())).order("date_added", desc=True).execute()
            resources = res.data if hasattr(res, "data") else res

            favorites_list = []
            for file in resources:
                file_id = file["id"]

                # Attach "date_favorited"
                file["date_favorited_raw"] = fav_map.get(file_id)

                # Format the date
                raw = file.get("date_favorited_raw")
                if raw:
                    try:
                        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                        file["date_favorited"] = dt.strftime("%b %d %Y, %I:%M %p")
                    except:
                        file["date_favorited"] = "Unknown"
                else:
                    file["date_favorited"] = "Unknown"

                # Flag for UI
                file["is_favorite"] = True

                favorites_list.append(file)

        return render(request, "favorites.html", {"favorites": favorites_list})

    except Exception as e:
        print(f"Fav Error: {e}")
        messages.error(request, f"Error loading favorites: {e}")
        return redirect("overview")
    

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------    


# ✅ Prevent caching so user can't back-button to login if already logged in
@login_required
@never_cache
def profiled(request):
    user = request.user # Current logged in user

    if request.method == "POST":
        action = request.POST.get('action')

        # --- 1. UPDATE INFO (Name, Bio, Username) ---
        if action == 'update_info':
            user.first_name = request.POST.get('first_name', user.first_name).strip()
            user.last_name = request.POST.get('last_name', user.last_name).strip()
            user.username = request.POST.get('username', user.username).strip()
            # ✅ NEW: Save Bio
            user.bio = request.POST.get('bio', '').strip()
            
            try:
                user.save()
                messages.success(request, "✅ Profile updated successfully.")
            except Exception as e:
                messages.error(request, "Error saving profile. Username might be taken.")
            
            return redirect('profiled')

        # --- 2. UPDATE AVATAR (Upload to Supabase) ---
        elif action == 'update_avatar':
            image_file = request.FILES.get('profile_image')
            
            if image_file:
                try:
                    # 1. Generate unique path: avatars/user_id/timestamp.jpg
                    file_ext = image_file.name.split('.')[-1]
                    file_path = f"avatars/{user.id}/{uuid.uuid4()}.{file_ext}"

                    # 2. Upload to Supabase
                    supabase.storage.from_(settings.SUPABASE_BUCKET).upload(
                        file_path,
                        image_file.read(),
                        {"content-type": image_file.content_type}
                    )

                    # 3. Get Public URL
                    public_url_res = supabase.storage.from_(settings.SUPABASE_BUCKET).get_public_url(file_path)
                    # Handle Supabase-py version differences
                    public_url = public_url_res if isinstance(public_url_res, str) else public_url_res.get('publicURL')

                    # 4. Save URL to Database
                    user.profile_picture = public_url
                    user.save()
                    
                    messages.success(request, "📸 Profile picture updated!")
                except Exception as e:
                    print(f"Avatar Upload Error: {e}")
                    messages.error(request, "Failed to upload image. Please try again.")
            
            return redirect('profiled')

        # --- 3. CHANGE PASSWORD ---
        elif action == 'change_password':
            old_pass = request.POST.get('old_password')
            new_pass = request.POST.get('new_password')
            confirm_pass = request.POST.get('confirm_password')

            # 1. Check Old Password
            if not user.check_password(old_pass):
                messages.error(request, "❌ Incorrect current password.")
            
            # 2. Check Confirmation
            elif new_pass != confirm_pass:
                messages.error(request, "❌ New passwords do not match.")
            
            # ✅ 3. Check Complexity (New Rules)
            elif len(new_pass) < 6:
                messages.error(request, "⚠️ Password must be at least 6 characters.")
            elif not re.search(r"[A-Z]", new_pass):
                messages.error(request, "⚠️ Password must contain an uppercase letter.")
            elif not re.search(r"[a-z]", new_pass):
                messages.error(request, "⚠️ Password must contain a lowercase letter.")
            elif not re.search(r"[0-9]", new_pass):
                messages.error(request, "⚠️ Password must contain a number.")
            elif not re.search(r"[!@#$%^&*]", new_pass):
                messages.error(request, "⚠️ Password must contain a special character.")
            
            else:
                user.set_password(new_pass)
                user.save()
                login(request, user) # Keep logged in
                messages.success(request, "🔒 Password changed successfully.")
            
            return redirect('profiled')

    return render(request, 'profiled.html', {'user': user})

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
def about(request):
    return render(request, 'about.html')

#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------

# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
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

# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
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

# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
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
# ✅ Prevent caching so user can't back-button to login if already logged in
@never_cache
def toggle_visibility(request, file_id):
    """
    View to toggle the visibility status of a file between 'public' and 'private'.
    
    HOW IT WORKS:
    1. Authentication & Validation: Checks if user is logged in and request is POST.
    2. Fetch Current State: Queries Supabase for the file's current visibility.
    3. Determine New State:
       - Toggles visibility (private <-> public).
       - Sets status based on new visibility (Public -> Pending, Private -> Approved).
    4. Update Database: Saves the new visibility, status, and modification timestamp.
    5. User Feedback: Displays a success message indicating the new state.
    """
    
    # 1. Security Check: Ensure user is logged in and method is POST (Action)
    user_id = request.session.get("user_id")
    if not user_id or request.method != "POST":
        # Redirect if unauthorized or wrong method (prevent CSRF/GET abuse)
        return redirect("uploads")

    try:
        # 2. Get Current State
        # Fetch the current 'visibility' of the specific file ID
        current_res = supabase.table('resources').select('visibility').eq('id', file_id).single().execute()
        current_data = current_res.data if hasattr(current_res, 'data') else current_res
        
        # 3. Toggle Logic
        # Swap values: If currently 'private', make it 'public', otherwise 'private'
        new_vis = 'public' if current_data['visibility'] == 'private' else 'private'
        
        # 4. Status Logic
        # If switching to Public -> Must go to 'pending' for Admin approval
        # If switching to Private -> Auto-set to 'approved' (safe for owner)
        new_status = 'pending' if new_vis == 'public' else 'approved'

        # 5. Execute Update
        # Update the record in Supabase with new visibility, status, and timestamp
        supabase.table('resources').update({
            'visibility': new_vis,
            'status': new_status,
            'date_changed': timezone.now().isoformat() # ✅ Track when the change happened
        }).eq('id', file_id).execute()

        # 6. Feedback Message
        if new_vis == 'public':
            messages.success(request, "File is now Public (Pending Approval).")
        else:
            messages.success(request, "File is now Private.")

    except Exception as e:
        # Log error and notify user if update fails
        messages.error(request, f"Error: {e}")

    # Redirect back to the uploads list
    return redirect('uploads')
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------------


# views.py 


from django.shortcuts import render, redirect
from django.http import HttpResponse
from supabase import create_client
from django.conf import settings    

 
supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

# def register(request):
#     if request.method == "POST":
#         # You can process form data here
#         first_name = request.POST.get("first_name")
#         last_name = request.POST.get("last_name")
#         email = request.POST.get("email")
#         password = request.POST.get("password")
#         confirm_password = request.POST.get("confirm_password")

#         if password != confirm_password:
#             return render(request, "register.html", {
#                 "error": "Passwords do not match!"
#             })
            
#         existing_user = supabase.table("users").select("*").eq("email", email).execute()
#         if existing_user.data:
#             return render(request, "register.html", {"error": "Gmail already being used!"})
        
#         existing_name = supabase.table("users").select("*").eq("first_name", first_name).eq("last_name", last_name).execute()
#         if existing_name.data:
#             return render(request, "register.html", {"error": "Name already existed!"})
        
#         supabase.table("users").insert({
#             "first_name": first_name,
#             "last_name": last_name,
#             "email": email,
#             "password": password
#         }).execute()
        
#         request.session["success_message"] = "Successfully created an account!"
#         return redirect("login")


#         # TODO: Save user to DB (using Django User model or custom model)

#     return render(request, "register.html")


# def login_view(request):
#     if request.method == "POST":
#         username = request.POST["username"]
#         password = request.POST["password"]
 
#         response = supabase.table("users").select("*").eq("username", username).execute()
 
#         if response.data and response.data[0]["password"] == password:
#             # return HttpResponse("Login successful!") 
#             request.session["user"] = response.data[0]["email"]
#             request.session["success_message"] = "Successfully logged in!"
#             return redirect("navbar")
#         else:
#             # return HttpResponse("Invalid credentials!")
#             return render(request, "login.html", {"error": "Invalid credentials!"})
 
#     return render(request, "login.html")
    

# def navbar(request):
#     user = request.session.get("user")
#     if not user:
#         return redirect("login")  # If not logged in, redirect to login
#     success_message = request.session.pop("success_message", None)
#     return render(request, "navbar.html", {"success": success_message})



def register(request):
    if request.method == "POST":
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        # ✅ 1. Password match validation
        if password != confirm_password:
            return render(request, "register.html", {"error": "Passwords do not match!"})

        # ✅ 2. Email already exists check
        existing_user = supabase.table("users").select("*").eq("email", email).execute()
        if existing_user.data:
            return render(request, "register.html", {"error": "Email already in use!"})

        # ✅ 3. Save new user in Supabase
        supabase.table("users").insert({
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": password
        }).execute()

        # ✅ 4. Auto-login after registration + success message
        request.session["user"] = email
        request.session["success_message"] = "Account successfully created!"
        return redirect("overview")

    return render(request, "register.html")


def login_view(request):
    if request.method == "POST":
        email = request.POST.get("emailAd")
        password = request.POST.get("password")

        response = supabase.table("users").select("*").eq("email", email).execute()

        if response.data and response.data[0]["password"] == password:
            request.session["user"] = email
            request.session["success_message"] = "Successfully logged in!"
            return redirect("overview") #navbar
        else:
            return render(request, "login.html", {"error": "Invalid credentials!"})

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

def logout_view(request):
    request.session.flush()
    return redirect("login")

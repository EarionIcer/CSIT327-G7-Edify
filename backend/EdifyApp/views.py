
# views.py 


from django.shortcuts import render, redirect
from django.http import HttpResponse
from supabase import create_client
from django.conf import settings
from .models import CustomUser
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
import bcrypt
 
supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

def register(request):
    if request.method == "POST":
        # You can process form data here
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        if password != confirm_password:
            return render(request, "register.html", {
                "error": "Passwords do not match!"
            })

        # TODO: Save user to DB (using Django User model or custom model)
         # Check if user already exists
        if CustomUser.objects.filter(email=email).exists():
            return render(request, "register.html", {"error": "Email already registered!"})

        # ✅ Validate password using Django’s built-in password validators
        try:
            validate_password(password)
        except ValidationError as e:
            # e.messages is a list; show the first or join them all
            return render(request, "register.html", {
                "error": " ".join(e.messages)
            })

        # ✅ Hash password using bcrypt
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Save to local Django DB
        CustomUser.objects.create(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_pw
        )

        # (Optional) Also save to Supabase
        supabase.table("users").insert({
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": hashed_pw  # Hashed version, not plain text
        }).execute()

        return render(request, "register.html", {
            "success": "Account created successfully!"
        })

    return render(request, "register.html")


def login_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
 
        response = supabase.table("users").select("*").eq("username", username).execute()
 
        if response.data and response.data[0]["password"] == password:
            return HttpResponse("Login successful!")
        else:
            return HttpResponse("Invalid credentials!")
 
    return render(request, "login.html")
    

def navbar(request):
    return render(request, "navbar.html")


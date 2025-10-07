
# views.py 


from django.shortcuts import render, redirect
from django.http import HttpResponse
from supabase import create_client
from django.conf import settings
 
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
    return render(request, 'navbar.html')


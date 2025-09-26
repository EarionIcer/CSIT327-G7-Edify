
# views.py
from django.shortcuts import render

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

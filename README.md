<<<<<<< HEAD
## testling bickling 
=======
# Edif

pip install "fastapi[all]" uvicorn supabase Django
pip install bcrypt
>>>>>>> 0df949d54d2bca936b9fd6fa40c7526df0bf9039


# views.py
def register(request):
    if request.method == "POST":
        first_name = request.POST["first_name"]
        last_name = request.POST["last_name"]
        email = request.POST["email"]
        password = request.POST["password"]
        confirm_password = request.POST["confirm_password"]

        # Check password match
        if password != confirm_password:
            return render(request, "authentication/register.html", {"error": "Passwords do not match!"})

        # Check if email already exists
        existing_user = supabase.table("users").select("*").eq("email", email).execute()
        if existing_user.data:  # If any record is found
            return render(request, "authentication/register.html", {"error": "Account already exists!", "email": email})

        # Hash password before saving
        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        # Insert into Supabase table
        supabase.table("users").insert({
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": hashed_pw
        }).execute()

        return redirect("/login/")  # after successful signup

    return render(request, "authentication/register.html")

def login_view(request):
    if request.method == "POST":
        email = request.POST["email"]
        password = request.POST["password"]

        # Check if user exists
        result = supabase.table("users").select("*").eq("email", email).execute()

        if not result.data:  # No account with this email
            return render(request, "authentication/login.html", {"error": "Invalid email or password."})

        user = result.data[0]

        # Check hashed password
        if bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            # Store user in session
            request.session["user_id"] = user["id"]
            request.session["user_name"] = f"{user['first_name']} {user['last_name']}"
            return redirect("/dashboard/")  # change to your landing page
        else:
            return render(request, "authentication/login.html", {"error": "Invalid email or password."})

    return render(request, "authentication/login.html")

def dashboard(request):
    if "user_id" not in request.session:
        return redirect("/login/")
    return render(request, "dashboard.html", {"user_name": request.session["user_name"]})


git pull origin main --allow-unrelated-histories

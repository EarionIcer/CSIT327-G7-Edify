from django.urls import path
from . import views
from django.shortcuts import redirect
from django.views.generic.base import RedirectView

urlpatterns = [
    # =========================================
    # 1. SYSTEM & UTILITIES
    # =========================================
    # Redirect root URL (/) to the login page automatically
    path('', lambda request: redirect('login')),
    
    # Fixes the "Favicon not found" 404 error by pointing to your logo
    path('favicon.ico', RedirectView.as_view(url='/static/img/Edify-logo.png', permanent=True)),
    
    # Optional: Helper route if you load the navbar asynchronously (can be removed if not used)
    path("navbar/", views.navbar, name="navbar"),


    # =========================================
    # 2. AUTHENTICATION (Login/Register)
    # =========================================
    path("register/", views.register, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    
    # Password Reset Flow
    path("forgot_password/", views.forgot_password_view, name="forgot_password"),
    # Handles the logic/AJAX for resetting the password
    path("reset_password/", views.reset_password_view, name="reset_password"), 


    # =========================================
    # 3. MAIN USER PAGES (Core)
    # =========================================
    path("overview/", views.overview, name="overview"),
    path("uploads/", views.uploads, name="uploads"),
    path("favorites/", views.favorites, name="favorites"),
    path('public/', views.public_files, name='public'), 
    
    # Profile & Information
    path('profile/', views.profiled, name='profiled'),
    path('about/', views.about, name='about'),


    # =========================================
    # 4. FILE ACTIONS (CRUD)
    # =========================================
    # Create
    path("addfiles/", views.add_files, name="addfiles"),
    
    # Read / Download
    path('view/<uuid:pk>/', views.view_file, name='view_file'),
    path('file/<uuid:file_id>/', views.file_detail, name='file_detail'),
    path("download/<uuid:file_id>/", views.download_file, name="download_file"),
    
    # Update
    path("edit_file/<str:file_id>/", views.edit_file, name="edit_file"),
    path('toggle_visibility/<str:file_id>/', views.toggle_visibility, name='toggle_visibility'),
    path("toggle_favorite/<uuid:id>/", views.toggle_favorite, name="toggle_favorite"),
    
    # Delete
    path("delete_file/<str:id>/", views.delete_file, name="delete_file"),


    # =========================================
    # 5. ADMIN PORTAL
    # =========================================
    # Main Dashboard
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    
    # Dedicated Management Pages
    path('admin-files/', views.admin_files, name='admin_files'),
    path('admin-users/', views.admin_users, name='admin_users'),
    
    # Admin Actions
    path('approve_file/<str:file_id>/', views.approve_file, name='approve_file'),
    path('delete_file_admin/<str:file_id>/', views.delete_file_admin, name='delete_file_admin'),
    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
]
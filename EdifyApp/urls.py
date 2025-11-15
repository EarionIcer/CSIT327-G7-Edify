#urls.py


from django.urls import path
from . import views
from django.shortcuts import redirect



urlpatterns = [
    path('', lambda request: redirect('login')),
    path("register/", views.register, name="register"),
    path("login/", views.login_view, name="login"),
    path("overview/", views.overview, name="overview"),
    path("owsearch/", views.owsearch, name="owsearch"),
    path("navbar/", views.navbar, name="navbar"),
    path("favorites/", views.favorites, name="favorites"),
    path('profile/', views.profiled, name='profiled'),
    path('about/', views.about, name='about'),
    path("uploads/", views.uploads, name="uploads"),
    path("addfiles/", views.add_files, name="addfiles"),
    path("logout/", views.logout_view, name="logout"),
    path('upload_file/', views.upload_file, name='upload_file'),
    path('view/<uuid:pk>/', views.view_file, name='view_file'),
    path("toggle_favorite/<uuid:id>/", views.toggle_favorite, name="toggle_favorite"),
    #path('uploads/<uuid:pk>/edit/', views.edit_file, name='edit_file'),
    path('file/<uuid:file_id>/', views.file_detail, name='file_detail'),
    path("download/<uuid:file_id>/", views.download_file, name="download_file"),
    # path("edit_file/<uuid:file_id>/", views.edit_file, name="edit_file"),
    path("edit_file/<str:file_id>/", views.edit_file, name="edit_file"),
    path("forgot-password/", views.forgot_password_view, name="forgot_password"),
    path("delete_file/<str:id>/", views.delete_file, name="delete_file"),

]

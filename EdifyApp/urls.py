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
    path('uploads/<uuid:pk>/favorite/', views.toggle_favorite, name='toggle_favorite'),
    path('uploads/<uuid:pk>/edit/', views.edit_file, name='edit_file'),
    path('uploads/<uuid:pk>/delete/', views.delete_file, name='delete_file'),
]

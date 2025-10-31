#urls.py


from django.urls import path
from . import views



urlpatterns = [
    
    path("register/", views.register, name="register"),
    path("login/", views.login_view, name="login"),
    path("overview/", views.overview, name="overview"),
    path("navbar/", views.navbar, name="navbar"),
    path("favorites/", views.favorites, name="favorites"),
    path('profile/', views.profiled, name='profiled'),
    path('about/', views.about, name='about'),
    path("uploads/", views.uploads, name="uploads"),
    path("addfiles/", views.add_files, name="addfiles"),
    path("logout/", views.logout_view, name="logout"),
    path('upload_file/', views.upload_file, name='upload_file'),
    
]

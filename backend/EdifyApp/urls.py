#urls.py


from django.urls import path
from . import views



urlpatterns = [
    
    path("register/", views.register, name="register"),
    path("login/", views.login_view, name="login"),
    path("overview/", views.overview, name="overview"),
    path("navbar/", views.navbar, name="navbar"),
    path("favorites/", views.favorites, name="favorites"),
    path("uploads/", views.uploads, name="uploads"),
    path("logout/", views.logout_view, name="logout"),
    
]

from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", views.home, name="home"),
    path("login/", views.google_login, name="login"),
    path("oauth2callback/", views.google_callback, name="oauth2callback"),
    path("logout/", views.logout_view, name="logout"),
]
from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name = "home"),
    path("register", views.register, name = "register"),
    path("login", views.login, name = "login"),
    path("logout", views.logout, name = "logout"),
    path("verify-email/<slug:username>", views.verify_email, name="verify_email"),
    path("resend-otp", views.resend_otp, name="resend_otp"),


]
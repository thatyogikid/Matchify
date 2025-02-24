from django.urls import path
from . import views
from .views import *

urlpatterns = [
    path("", views.home, name = "home"),
    path("register", views.register, name = "register"),
    path("login", views.login, name = "login"),
    path("logout", views.logout, name = "logout"),
    path("verify-email/<slug:username>", views.verify_email, name="verify_email"),
    path("resend-otp", views.resend_otp, name="resend_otp"),
    path("auth-url", AuthenticationURL.as_view(), name="auth-url"),
    path("redirect/", views.spotify_redirect, name="redirect"),
    path("check-auth", CheckAuthentication.as_view(), name="check-auth"),
    path("success", views.success, name="success"),
    path("top-artists", views.top_artists, name="top_artists"),
    path("profile", views.profile, name="profile"),
    path("send-friend-request/<str:username>", views.send_friend_request, name="send_friend_request"),
    path("accept-friend-request/<str:username>", views.accept_friend_request, name="accept_friend_request"),
    path("reject-friend-request/<str:username>", views.reject_friend_request, name="reject_friend_request"),
    path("remove-friend/<str:username>", views.remove_friend, name="remove_friend"),
]
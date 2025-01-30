import random
import logging
from django.shortcuts import render, redirect, get_object_or_404
from .models import OtpToken
from django.contrib import messages
from django.contrib.auth import get_user_model, authenticate, login as auth_login, logout as auth_logout
from django.utils import timezone
from rest_framework import status
from rest_framework import response
from rest_framework.views import APIView
from django.contrib.auth.models import auth
from django.core.mail import send_mail
from django.db.models.signals import post_save
from django.contrib.auth import get_user_model
from .forms import LoginForm, RegisterForm
import base64
from requests import post, get, Request
import json
from . import extras
from .models import spotifyToken
from spotipy import Spotify
from .credentials import CLIENT_ID, CLIENT_SECRET, REDIRECT_URI

logger = logging.getLogger(__name__)

# Create your views here.
def login(request):
    if request.method == "POST":
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            identifier = form.cleaned_data["username"]
            password = form.cleaned_data["password"]
            
            # Check if the identifier is an email or username
            if '@' in identifier:
                try:
                    user = get_user_model().objects.get(email=identifier)
                    username = user.username
                except get_user_model().DoesNotExist:
                    messages.error(request, "Invalid Credentials")
                    return redirect("login")
            else:
                username = identifier
            
            user = authenticate(request, username=username, password=password)

            if user is not None:
                auth_login(request, user)
                return redirect("/")
            else:
                messages.error(request, "Invalid Credentials")
                return redirect("login")
    else:
        form = LoginForm()
    return render(request, "login.html", {"form": form})

def logout(request):
    auth_logout(request)
    return redirect("/")

def home(request):
    return render(request, "home.html")

def cleanup_expired_otps():
    OtpToken.objects.filter(otp_expires_at__lt=timezone.now()).delete()

def generate_otp():
    return ''.join(random.choices('0123456789', k=6))


def verify_email(request, username):
    cleanup_expired_otps()
    user = get_object_or_404(get_user_model(), username=username)
    user_otp = OtpToken.objects.filter(user=user, otp_code=request.POST.get('otp_code')).last()

    if request.method == 'POST':
        if user_otp:
            if user_otp.otp_expires_at > timezone.now():
                user.is_active = True
                user.save()
                messages.success(request, "Email verified successfully! You can now login.")
                return redirect("login")
            else:
                messages.warning(request, "OTP has expired.")
                return redirect("verify_email", username=user.username)
        else:
            messages.warning(request, "Invalid OTP.")
            return redirect("verify_email", username=user.username)
    
    context = {"username": username}
    return render(request, "verifyOTP.html", context)

def send_otp_email(user):
    otp_code = generate_otp()
    otp = OtpToken.objects.create(user=user, otp_code=otp_code, otp_expires_at=timezone.now() + timezone.timedelta(minutes=45))
    
    # email variables
    subject = "Email Verification"
    message = f"""
    Hi {user.username},  
                                
                                Welcome to Matchify! Here is your OTP: 

                                            {otp.otp_code} 

                                Code expires in 45 minutes, use the url below to go back to the website
                                http://127.0.0.1:8000/verify-email/{user.username}
    """
    sender = "matchify.me@gmail.com"
    receiver = [user.email]
    
    try:
        # send email
        send_mail(
            subject,
            message,
            sender,
            receiver,
            fail_silently=False,
        )
        logger.info(f"OTP email sent to {user.email}")
    except Exception as e:
        logger.error(f"Failed to send OTP email to {user.email}: {e}")

def resend_otp(request):
    if request.method == 'POST':
        user_email = request.POST["otp_email"]
        if get_user_model().objects.filter(email=user_email).exists():
            if get_user_model().objects.get(email=user_email).is_active:
                messages.info(request, "This email is already verified")
            else:
                user = get_user_model().objects.get(email=user_email)
                send_otp_email(user)
                messages.success(request, "A new OTP has been sent to your email address")
                return redirect("verify_email", username=user.username)
        else:
            messages.warning(request, "This email doesn't exist in the database")
            return redirect("resend_otp")
        
    context = {}
    return render(request, "resendOTP.html", context)

def user_post_save(sender, instance, created, **kwargs):
    if created:
        send_otp_email(instance)
    User = get_user_model()
    post_save.connect(user_post_save, sender=User)

def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            passwordrepeat = form.cleaned_data['passwordrepeat']

            if len(password) <= 8:
                messages.info(request, 'Password Must Be At Least 8 Characters')   
            if password == passwordrepeat:
                if get_user_model().objects.filter(email=email).exists():
                    messages.info(request, 'Email Already Used')
                    return redirect('register')
                elif get_user_model().objects.filter(username=username).exists():
                    messages.info(request, 'Username Already Taken')
                    return redirect('register')
                else:
                    user = get_user_model().objects.create_user(username=username, email=email, password=password)
                    user.is_active = False
                    user.save()
                    send_otp_email(user)
                    messages.success(request, "Account created successfully! An OTP was sent to your Email")
                    return redirect("verify_email", username=username)
            else:
                messages.info(request, 'Passwords Do Not Match')
                return redirect('register')
    else:
        form = RegisterForm()
    return render(request, 'register.html', {"form": form})

class AuthenticationURL(APIView):
    def get(self, request, format = None):
        scopes = "user-top-read"
        url = Request("GET", "https://accounts.spotify.com/authorize", params= {
            "scope" : scopes,
            "response_type" : "code",
            "redirect_uri" : REDIRECT_URI,
            "client_id": CLIENT_ID
        }).prepare().url
        return redirect(url)
    
def spotify_redirect(request, format = None):
    code = request.GET.get("code")
    error = request.GET.get("error")

    if error:
        return error

    response = post("https://accounts.spotify.com/api/token", data = {
        "grant_type" : "authorization_code",
        "code" : code,
        "redirect_uri" : REDIRECT_URI,
        "client_id" : CLIENT_ID,
        "client_secret" : CLIENT_SECRET
    }).json()

    access_token = response.get("access_token")
    refresh_token = response.get("refresh_token")
    expires_in = response.get("expires_in")
    token_type = response.get("token_type")

    authKey = request.session.session_key
    if not request.session.exists(authKey):
        request.session.create()
        authKey = request.session.session_key

    extras.create_or_update_spotifyTokens(
        session_id = authKey,
        access_token = access_token,
        refresh_token = refresh_token,
        expires_in = expires_in,
        token_type = token_type
    )
    redirect_url = "http://127.0.0.1:8000/success"
    return redirect(redirect_url)

def success(request, format = None):
    return render(request, "success.html")

class CheckAuthentication(APIView):
    def get(self, request, format = None):
        key = self.request.session.session_key
        if not self.request.session.exists(key):
            self.request.session.create()
            key = self.request.session.session_key
        
        auth_status = extras.is_spotify_authenticated(key)

        if auth_status:
            redirect_url = "http://127.0.0.1:8000/success"
            return redirect(redirect_url)
        else:
            redirect_url = "http://127.0.0.1:8000/auth-url"
            return redirect(redirect_url)


client_id = CLIENT_ID
client_secret = CLIENT_SECRET

def get_token(user):
    user_spotify_token = spotifyToken.objects.filter(user=user)
    return user_spotify_token

def get_auth_header(user):
    token = get_token(user)
    return {
        "Authorization": "Bearer " + token
    }

def search_for_artist(token, artist_name):
    url = "https://api.spotify.com/v1/search"
    headers = get_auth_header(token)
    query = f"?q={artist_name}&type=artist&limit=1"
    query_url = url + query
    result = get(query_url, headers=headers)
    json_result = json.loads(result.content)["artists"]["items"]
    if len(json_result) == 0:
        print("No artist found")
        return None
    return json_result[0]

def get_top_artists(user):
    token = get_token(user)
    url = "http://api.spotify.com/v1/"
    query = "me/top/artists"
    query_url = url + query
    headers = get_auth_header(token)
    result = get(query_url, headers=headers)
    json_result = json.loads(result.content)["tracks"]
    return json_result

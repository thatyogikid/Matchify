from datetime import timedelta
import random
import logging
from django.shortcuts import render, redirect, get_object_or_404
from .models import OtpToken, FriendRequest, Friendship
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
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from rest_framework.response import Response
from django.conf import settings
import requests
from django.http import JsonResponse
from django.urls import reverse
from django.db.models import Q

logger = logging.getLogger(__name__)

# Create your views here.
from django.http import JsonResponse
from django.shortcuts import render
from django.contrib.auth import authenticate, login as auth_login
from .forms import LoginForm

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
                    return JsonResponse({
                        'success': False,
                        'messages': ["Invalid Credentials"],
                        'reset_captcha': True  # Flag to reset CAPTCHA
                    })
            else:
                username = identifier
            
            user = authenticate(request, username=username, password=password)

            if user is not None:
                auth_login(request, user)
                return JsonResponse({'success': True, 'redirect_url': '/'})
            else:
                return JsonResponse({
                    'success': False,
                    'messages': ["Invalid Credentials"],
                    'reset_captcha': True  # Flag to reset CAPTCHA
                })
        else:
            # Flatten form errors into a list of strings, excluding "__all__"
            errors = []
            for field, error_list in form.errors.items():
                if field == "__all__":
                    # Handle non-field errors separately
                    errors.extend(error_list)
                else:
                    # Handle field-specific errors
                    for error in error_list:
                        errors.append(f"{field}: {error}")
            return JsonResponse({
                'success': False,
                'messages': errors,
                'reset_captcha': True  # Flag to reset CAPTCHA
            })
    else:
        form = LoginForm()
    return render(request, "login.html", {"form": form})

def logout(request):
    auth_logout(request)
    return redirect("/")

def home(request):
    return render(request, 'home.html')

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

from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from .forms import RegisterForm

def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            passwordrepeat = form.cleaned_data['passwordrepeat']

            # Validate password length
            if len(password) < 8:
                return JsonResponse({'success': False, 'reset_captcha': True, 'messages': ['Password must be at least 8 characters.']})

            # Check if passwords match
            if password != passwordrepeat:
                return JsonResponse({'success': False,'reset_captcha': True, 'messages': ['Passwords do not match.']})

            # Check if email is already used
            if get_user_model().objects.filter(email=email).exists():
                return JsonResponse({'success': False, 'reset_captcha': True, 'messages': ['Email is already used.']})

            # Check if username is already taken
            if get_user_model().objects.filter(username=username).exists():
                return JsonResponse({'success': False, 'reset_captcha': True, 'messages': ['Username is already taken.']})

            # Create the user
            user = get_user_model().objects.create_user(username=username, email=email, password=password)
            user.is_active = False
            user.save()

            # Send OTP email
            send_otp_email(user)

            # Return success response
            return JsonResponse({
                'success': True,
                'redirect_url': reverse('verify_email', args=[username]),  # Redirect to verify_email page
                'messages': ['Account created successfully! An OTP was sent to your email.']
            })
        else:
            # Flatten form errors into a list of strings, excluding "__all__"
            errors = []
            for field, error_list in form.errors.items():
                if field == "__all__":
                    # Handle non-field errors separately
                    errors.extend(error_list)
                else:
                    # Handle field-specific errors
                    for error in error_list:
                        errors.append(f"{field}: {error}")
            return JsonResponse({'success': False, 'reset_captcha': True, 'messages': errors})
    else:
        form = RegisterForm()
    return render(request, 'register.html', {"form": form})

@method_decorator(login_required, name='dispatch')
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

@login_required
def spotify_redirect(request, format=None):
    code = request.GET.get("code")
    error = request.GET.get("error")

    if error:
        print(f"Spotify auth error: {error}")  # Debug print
        return error

    response = post("https://accounts.spotify.com/api/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }).json()

    print("Spotify token response:", response)  # Debug print

    access_token = response.get("access_token")
    refresh_token = response.get("refresh_token")
    expires_in = response.get("expires_in")
    token_type = response.get("token_type")

    if not all([access_token, refresh_token, expires_in, token_type]):
        print("Missing token data:", response)  # Debug print
        return redirect('home')

    expires_at = timezone.now() + timedelta(seconds=expires_in)

    # Print debug info
    print(f"Saving token for user: {request.user.username}")
    print(f"Access token: {access_token[:10]}...")  # Only print first 10 chars

    extras.create_or_update_spotifyTokens(
        user=request.user,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_at,
        token_type=token_type
    )

    redirect_url = "http://127.0.0.1:8000/success"
    return redirect(redirect_url)


class CheckAuthentication(APIView):
    def get(self, request, format=None):
        if not request.user.is_authenticated:
            return redirect('login')  # Redirect to login page if not authenticated

        user = request.user  # Directly use the logged-in user
        auth_status = extras.is_spotify_authenticated(user)

        if auth_status:
            redirect_url = "http://127.0.0.1:8000/success"
            return redirect(redirect_url)
        else:
            redirect_url = "http://127.0.0.1:8000/auth-url"
            return redirect(redirect_url)
client_id = CLIENT_ID
client_secret = CLIENT_SECRET

def get_token(user):
    try:
        token = spotifyToken.objects.get(user=user)  # Retrieve a single token object
        return token.access_token
    except spotifyToken.DoesNotExist:
        return None
    

def get_auth_header(user):
    token = get_token(user)
    if token:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    else:
        return None

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

def get_top_artists(user, time_range='medium_term'):
    token = get_token(user)
    print("Checking token:", token is not None)  # Debug print
    
    if not token:
        print("No token found for user:", user.username)  # Debug print
        return {'Error': 'No valid token found.'}

    # Spotify API endpoint for top artists
    url = "https://api.spotify.com/v1/me/top/artists"

    # Headers for the API request
    headers = get_auth_header(user)
    if not headers:
        return {'Error': 'No valid token found.'}

    # Query parameters
    params = {
        'time_range': time_range,
        'limit': 10
    }

    # Make the API request
    print("Making request to:", url)  # Debug print
    print("With headers:", headers)  # Debug print
    print("With params:", params)  # Debug print
    
    result = get(url, headers=headers, params=params)
    
    print("Response status code:", result.status_code)  # Debug print
    print("Response content:", result.content)  # Debug print

    # Parse the response
    try:
        json_result = result.json()
        if 'items' in json_result:
            return json_result['items']
        else:
            print("JSON response but no items:", json_result)  # Debug print
            return {'Error': 'No top artists found.'}
    except Exception as e:
        print("Failed to parse JSON:", str(e))  # Debug print
        print("Raw response:", result.content)  # Debug print
        return {'Error': f'Issue with request: {str(e)}'}
    
@login_required
def top_artists(request):
    # Get the time_range parameter from the request (default to 'medium_term')
    time_range = request.GET.get('time_range', 'medium_term')

    # Fetch top artists from Spotify
    top_artists = get_top_artists(request.user, time_range)

    # Handle errors
    if 'Error' in top_artists:
        return render(request, "topartists.html", {
            "error": top_artists['Error'],
            "time_range": time_range
        })

    return render(request, "topartists.html", {
        "top_artists": top_artists,
        "time_range": time_range
    })


def success(request):
    return render(request, "success.html")

@login_required
def profile(request):
    current_user = request.user
    current_user_spotify = extras.is_spotify_authenticated(current_user)
    
    # Get friend filter preference
    show_friends_only = request.GET.get('friends_only') == 'true'
    
    # Get all friendships for the current user
    friends = get_user_model().objects.filter(
        Q(friendships1__user2=current_user) | 
        Q(friendships2__user1=current_user)
    )
    
    # Get pending friend requests
    received_requests = FriendRequest.objects.filter(to_user=current_user)
    sent_requests = FriendRequest.objects.filter(from_user=current_user)
    
    # Get other users based on filter
    User = get_user_model()
    if show_friends_only:
        other_users = friends
    else:
        other_users = User.objects.exclude(id=current_user.id).exclude(is_superuser=True)
    
    users_data = []
    
    # Add current user's data
    current_user_data = {
        'user': current_user,
        'spotify_connected': current_user_spotify,
        'top_artists': None,
        'is_current_user': True
    }
    
    if current_user_spotify:
        try:
            artists = get_top_artists(current_user, time_range='medium_term')
            if not isinstance(artists, dict):
                current_user_data['top_artists'] = artists
        except Exception as e:
            print(f"Error getting current user's artists: {str(e)}")
    
    users_data.append(current_user_data)
    
    # Add other users' data
    for user in other_users:
        try:
            spotify_connected = extras.is_spotify_authenticated(user)
            user_data = {
                'user': user,
                'spotify_connected': spotify_connected,
                'top_artists': None,
                'is_current_user': False,
                'is_friend': user in friends,
                'friend_request_sent': sent_requests.filter(to_user=user).exists(),
                'friend_request_received': received_requests.filter(from_user=user).exists(),
            }
            
            if spotify_connected:
                try:
                    artists = get_top_artists(user, time_range='medium_term')
                    if not isinstance(artists, dict):
                        user_data['top_artists'] = artists
                except:
                    pass
                    
            users_data.append(user_data)
        except Exception as e:
            print(f"Error processing user {user.username}: {str(e)}")
            continue
    
    return render(request, "profile.html", {
        'users_data': users_data,
        'received_requests': received_requests,
        'show_friends_only': show_friends_only
    })

@login_required
def send_friend_request(request, username):
    to_user = get_object_or_404(get_user_model(), username=username)
    FriendRequest.objects.create(from_user=request.user, to_user=to_user)
    return redirect('profile')

@login_required
def accept_friend_request(request, username):
    from_user = get_object_or_404(get_user_model(), username=username)
    friend_request = get_object_or_404(FriendRequest, from_user=from_user, to_user=request.user)
    
    # Create friendship
    Friendship.objects.create(user1=request.user, user2=from_user)
    
    # Delete the request
    friend_request.delete()
    return redirect('profile')

@login_required
def reject_friend_request(request, username):
    from_user = get_object_or_404(get_user_model(), username=username)
    friend_request = get_object_or_404(FriendRequest, from_user=from_user, to_user=request.user)
    friend_request.delete()
    return redirect('profile')

@login_required
def remove_friend(request, username):
    friend = get_object_or_404(get_user_model(), username=username)
    Friendship.objects.filter(
        Q(user1=request.user, user2=friend) | 
        Q(user1=friend, user2=request.user)
    ).delete()
    return redirect('profile')
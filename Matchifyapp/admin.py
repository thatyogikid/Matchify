from django.contrib import admin
from .models import OtpToken, spotifyToken
from django.contrib.auth.admin import UserAdmin

# Register your models here.
class OtpTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "otp_code")

class SpotifyTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "access_token", "token_type", "expires_in", "created_at")

admin.site.register(OtpToken, OtpTokenAdmin)
admin.site.register(spotifyToken, SpotifyTokenAdmin)
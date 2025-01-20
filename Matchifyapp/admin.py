from django.contrib import admin
from .models import OtpToken
from django.contrib.auth.admin import UserAdmin

# Register your models here.
class OtpTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "otp_code")


admin.site.register(OtpToken, OtpTokenAdmin)
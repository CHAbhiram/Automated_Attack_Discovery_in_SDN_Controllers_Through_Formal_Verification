from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

class CustomUserAdmin(UserAdmin):
    list_display = ['username', 'email', 'role', 'is_active', 'date_joined']
    list_filter = ['role', 'is_active']
    fieldsets = UserAdmin.fieldsets + (
        ('SDN System', {'fields': ('role', 'department', 'phone', 'is_approved')}),
    )

admin.site.register(CustomUser, CustomUserAdmin)
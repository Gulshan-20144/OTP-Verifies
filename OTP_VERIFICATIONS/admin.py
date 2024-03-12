from django.contrib import admin
from .models import *
# Register your models here.
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display=['id','username','firstname','lastname','email','date_of_birth','is_admin','verified']
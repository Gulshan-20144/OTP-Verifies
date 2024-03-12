from django.db import models

# Create your models here.
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
import uuid

#CUSTOM USER MANAGER
class UserManager(BaseUserManager):
    
    def create_user(self, username, email, firstname, lastname, date_of_birth, password=None, **extra_fields):
        """
            Creates and saves a User with the given username, email, date of
            birth, name, and password.
            """
        if not username:
            raise ValueError("Users must have a username")

        user = self.model(
            username=username,
            email=email,
            firstname=firstname,
            lastname=lastname,
            date_of_birth=date_of_birth,
            **extra_fields
        )

        user.set_password(password)
        user.save(using=self._db)
        return user 

    def create_superuser(self, username, email, firstname, lastname, date_of_birth, password=None, **extra_fields):
        """
        Creates and saves a superuser with the given username, email, date of
        birth, name, and password.
        """
        

        user=self.create_user(
            username=username,
            email=email,
            firstname=firstname,
            lastname=lastname,
            password=password,
            date_of_birth=date_of_birth,
            **extra_fields
        )
        user.is_admin = True
        user.save(using=self._db)
        return user

    
#custum user model
class User(AbstractBaseUser):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        unique=True
    )
    username=models.CharField(
        max_length=100,
        verbose_name="username",
        unique=True,
        blank=False,
        null=False,
        )
    email = models.EmailField(
        verbose_name="email address",
        max_length=255,
    )
    firstname=models.CharField(max_length=100,blank=False,null=False)
    lastname=models.CharField(max_length=100,blank=True,null=True)
    date_of_birth = models.DateField(blank=True,null=True)
    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_admin = models.BooleanField(default=False)
    otp = models.CharField(max_length=6)
    verified = models.BooleanField(default=False)
    
    objects = UserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS=['firstname','lastname','email',"date_of_birth"]
    
    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin

    
    
    
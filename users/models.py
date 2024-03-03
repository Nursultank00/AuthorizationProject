from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin

from .utils import char_validator

from uuid import uuid4
# Create your models here.

class UserManager(BaseUserManager):

    def create_superuser(self, username, email, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(username, email, password, **extra_fields)

    def create_user(self, username, email, password, **extra_fields):
        if not username:
            raise ValueError()
        if not email:
            raise ValueError()
        email = self.normalize_email(email)
        user = self.model(username = username, email = email, **extra_fields)
        user.set_password(password)
        user.save()
        return user
    
class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key = True, default = uuid4, editable = False)
    username = models.CharField(max_length = 30, unique = True, validators = [char_validator])
    email = models.EmailField(unique = True)
    is_staff = models.BooleanField(default = False)
    is_superuser = models.BooleanField(default = False)
    email_verified = models.BooleanField(default = False)
    created_at = models.DateTimeField(auto_now_add = True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']
    objects = UserManager()

    def __str__(self):
        return self.username
    
class ConfirmationCode(models.Model):
    user = models.OneToOneField(User, related_name = 'code', on_delete = models.CASCADE)
    code = models.TextField()

    def __str__(self):
        return self.user.username + "'s confirmation code"

from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password
from django.db import models


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    facial_data = models.JSONField(null=True, blank=True)
    password = models.CharField(max_length=128)
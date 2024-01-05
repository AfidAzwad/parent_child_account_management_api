from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    is_parent = models.BooleanField(default=False)
    is_child = models.BooleanField(default=False)
    parent_id = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, related_name='childs')
    
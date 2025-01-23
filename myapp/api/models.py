import datetime
from constance import config
from django.db import models
from django.conf import settings

def get_expiry_time():
    return datetime.datetime.now() + config.REFRESH_TOKEN_LIFETIME


class RefreshToken(models.Model):
    refresh_token = models.CharField(max_length=36)
    expiry_time = models.DateTimeField(default=get_expiry_time)
    user = models.OneToOneField(settings.AUTH_USER_MODEL,
                                on_delete=models.CASCADE)

    def __str__(self):
        return str(self.refresh_token)

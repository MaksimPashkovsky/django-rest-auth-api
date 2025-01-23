from datetime import datetime

import jwt
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication
from .models import RefreshToken
from .serializers import UserInSerializer


class EmailAuthentication(BaseAuthentication):
    def authenticate(self, request):

        serializer = UserInSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            password = serializer.data['password']
            email = serializer.data['email']
        except KeyError:
            return None

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('No such user!')

        try:
            rt = RefreshToken.objects.get(user=user)
        except RefreshToken.DoesNotExist:
            pass
        else:
            raise exceptions.AuthenticationFailed('User already logged!')

        password_valid = check_password(password, user.password)

        if not password_valid:
            raise exceptions.AuthenticationFailed('Invalid password!')

        return (user, None)


class JsonWebTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):

        try:
            auth_header = request.META['HTTP_AUTHORIZATION']
        except KeyError:
            return None

        if not auth_header.startswith('Bearer '):
            return None

        try:
            access_token = auth_header.split(' ')[1]
        except IndexError:
            return None

        try:
            decoded_jwt = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.exceptions.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('JWT Signature has expired!')
        except jwt.exceptions.InvalidSignatureError:
            raise exceptions.AuthenticationFailed('JWT Signature verification failed')
        except jwt.exceptions.DecodeError:
            raise exceptions.AuthenticationFailed('Cannot decode JWT!')

        user = User.objects.get(email=decoded_jwt['email'])

        try:
            refresh_token = RefreshToken.objects.get(user_id=user.id)
        except RefreshToken.DoesNotExist:
            raise exceptions.AuthenticationFailed('User logged out')

        if refresh_token.expiry_time.replace(tzinfo=None) <= datetime.now():
            refresh_token.delete()
            raise exceptions.AuthenticationFailed('Refresh token expired!')

        return (user, None)

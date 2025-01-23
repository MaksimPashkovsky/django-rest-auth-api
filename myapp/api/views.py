import datetime
import uuid
import jwt
from django.conf import settings
from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from constance import config
from .models import RefreshToken
from .serializers import UserOutSerializer, UserInSerializer, RefreshTokenSerializer
from .authentication import EmailAuthentication, JsonWebTokenAuthentication


class RegisterAPIView(APIView):
    """
    Register a new account in the system by password and email.
    Returns new user id and email
    """

    def perform_authentication(self, request):
        pass

    def post(self, request):
        serializer = UserInSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            user = serializer.save()
        except serializers.ValidationError:
            return Response({'detail': 'User cannot be created!'}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'id': user.id, 'email': user.email}, status=status.HTTP_201_CREATED)

class LoginAPIView(APIView):
    """
    Authentication via email and password.
    Obtaining access and refresh tokens
    """
    authentication_classes = [EmailAuthentication]

    def post(self, request):

        user = request.user

        try:
            refresh_token = RefreshToken.objects.get(user_id=user.id)
        except RefreshToken.DoesNotExist:
            refresh_token = RefreshToken(refresh_token=str(uuid.uuid4()), user_id=user.id)
            refresh_token.save()

        payload = {"id": user.id,
                   'email': user.email,
                   'exp': datetime.datetime.now() + config.ACCESS_TOKEN_LIFETIME,
                   'iat': datetime.datetime.now()}
        print(payload)
        encoded_jwt = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

        return Response({'access_token': encoded_jwt,
                         'refresh_token': refresh_token.refresh_token})


class RefreshAPIView(APIView):
    """
    Refreshing the tokens.
    Returns new access and refresh tokens
    """

    def perform_authentication(self, request):
        pass

    def post(self, request):
        serializer = RefreshTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.data['refresh_token']

        try:
            old_refresh_token = RefreshToken.objects.get(refresh_token=refresh_token)
        except RefreshToken.DoesNotExist:
            return Response({'detail': 'User logged out'})
        user = old_refresh_token.user
        old_refresh_token.delete()

        new_refresh_token = RefreshToken(refresh_token=str(uuid.uuid4()), user_id=user.id)
        new_refresh_token.save()

        payload = {"id": user.id,
                   'email': user.email,
                   'exp': datetime.datetime.now() + config.ACCESS_TOKEN_LIFETIME,
                   'iat': datetime.datetime.now()}
        print(payload)
        encoded_jwt = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

        return Response({'access_token': encoded_jwt,
                         'refresh_token': new_refresh_token.refresh_token})

class LogoutAPIView(APIView):
    """
    Logout.
    Invalidating refresh token
    """
    def perform_authentication(self, request):
        pass

    def post(self, request):
        serializer = RefreshTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        refresh_token = serializer.data['refresh_token']
        try:
            old_refresh_token = RefreshToken.objects.get(refresh_token=refresh_token)
        except RefreshToken.DoesNotExist:
            return Response({'detail': 'User not logged'})
        old_refresh_token.delete()
        return Response({"success": "User logged out."})


class UserAPIView(APIView):
    """
    Personal information page
    """
    authentication_classes = [JsonWebTokenAuthentication]

    def get(self, request):
        user = request.user
        if user.is_anonymous:
            return Response({"detail": 'Not authorized access'}, status=status.HTTP_403_FORBIDDEN)
        user_serializer = UserOutSerializer(user)
        return Response(user_serializer.data)

    def put(self, request):
        user = request.user
        if user.is_anonymous:
            return Response({"detail": 'Not authorized access'}, status=status.HTTP_403_FORBIDDEN)
        new_username = request.data['username']
        user.username = new_username
        user.save()
        user_serializer = UserOutSerializer(user)
        return Response(user_serializer.data)

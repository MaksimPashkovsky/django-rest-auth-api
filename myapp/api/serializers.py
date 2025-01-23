from rest_framework import serializers
from django.db.utils import IntegrityError
from django.contrib.auth.models import User
from .models import RefreshToken


class UserInSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=100, min_length=12)
    email = serializers.EmailField()

    def create(self, validated_data):
        password = validated_data['password']
        email = validated_data['email']
        try:
            user = User.objects.create_user(username=email.split('@')[0], email=email, password=password)
        except IntegrityError:
            raise serializers.ValidationError('Cannot create user!')
        user.save()
        return user


class RefreshTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = RefreshToken
        fields = ('refresh_token', )



class UserOutSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email')


from drf_yasg import openapi
from rest_framework import serializers

from .serializers import LoginSerializer

class LoginOpenAPISerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField()
    user_info = LoginSerializer()

class ErrorMessageSerializer(serializers.Serializer):
    error_message = serializers.CharField(max_length = 255)

class SuccessMessageSerializer(serializers.Serializer):
    success_message = serializers.CharField(max_length = 255)


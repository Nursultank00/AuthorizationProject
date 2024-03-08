from django.contrib.auth import get_user_model

from rest_framework import serializers

User = get_user_model()

class SignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'read_only': True}
        }

    def create(self, validated_date):
        user = User.objects.create_user(username = validated_date['username'],
                                        email = validated_date['email'],
                                        password = validated_date['password'])
        return user
    
class LoginSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = ['username', 'password']

class MailSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = ['email']

class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
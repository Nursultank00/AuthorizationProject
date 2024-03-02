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
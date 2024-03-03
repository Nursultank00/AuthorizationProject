from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.views import Response, status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
# Create your views here.
from users.serializers import SignupSerializer, LoginSerializer, LogoutSerializer

from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings

from .models import User, ConfirmationCode
from .utils import EmailUtil

import jwt
from datetime import timedelta
class SignupAPIView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = SignupSerializer(data = request.data)
        if serializer.is_valid():
            try:
                serializer.save()
            except Exception as e:
                return Response({"message: ": e.message}, status=status.HTTP_400_BAD_REQUEST)
            
            user_data = serializer.data
            user = User.objects.get(email = user_data['email'])
            token = RefreshToken().for_user(user).access_token
            token.set_exp(lifetime=timedelta(minutes=5))
            ConfirmationCode.objects.create(user = user, code = str(token))
            current_site = get_current_site(request).domain
            relativeLink = reverse('authproject-email-verify')
            
            absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
            email_body = 'Hi '+ user.username + '! The link below is to verify your email \n' + absurl

            data = {'email_body':email_body,'to_email':user.email,
                    'email_subject':'Verify your email'}
            
            EmailUtil.send_email(data)
            return Response({'email': serializer.data['email']}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailAPIView(APIView):
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(id=payload['user_id'])
            if user.email_verified:
                return Response({'Message':'User is already verified'}, status=status.HTTP_200_OK)
            user_code = ConfirmationCode.objects.get(user = user)
            if token != user_code.code:
                return Response({'Message':'Activation token expired'}, status=status.HTTP_400_BAD_REQUEST)
            user.email_verified = True
            user.save()
            return Response({'Message':'User is successfuly verified'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({'Error':'Activation token expired'}, status=status.HTTP_400_BAD_REQUEST)
        # except jwt.exceptions.DecodeError as identifier:
        except jwt.exceptions.DecodeError:
            return Response({'Error':'invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        username = request.data['username']
        password = request.data['password']
        user = User.objects.filter(username = username).first()
        if user is None:
            return Response({'Error':'No user with this username'}, status.HTTP_404_NOT_FOUND)
        if not user.check_password(password):
            raise AuthenticationFailed({'Error':'Wrong password!'})
        if not user.email_verified:
            return AuthenticationFailed({'Error':'Username email is not verified!'})
        refresh = RefreshToken.for_user(user)

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })
    
class TokenRefreshView(TokenRefreshView):

    def post(self, *args, **kwargs):
        return super().post(*args, **kwargs)
    

class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = LogoutSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.validated_data["refresh_token"]

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"Message": "You have successfully logged out."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"Error": "Unable to log out."}, status=status.HTTP_400_BAD_REQUEST)
        
class ResendVerifyEmailAPIView(APIView):
    serializer_class = SignupSerializer

    def post(self, request):
        data = request.data
        email = data['email']
        try:
            user = User.objects.get(email=email)
            if user.email_verified:
                return Response({'Message':'User is already verified'}, status=status.HTTP_200_OK)
            token = RefreshToken().for_user(user).access_token
            token.set_exp(lifetime=timedelta(minutes=5))

            user_code = ConfirmationCode.objects.get(user = user)
            user_code.code = str(token)
            user_code.save()
            
            current_site = get_current_site(request).domain
            relativeLink = reverse('authproject-email-verify')
            absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
            email_body = 'Hi '+ user.username + '! The link below is to verify your email \n' + absurl

            data = {'email_body':email_body,'to_email':user.email,
                    'email_subject':'Verify your email'}
            EmailUtil.send_email(data)
            return Response({'Message':'The verification email has been sent'}, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response({'Message':'No such user, register first'})
from django.urls import path
from users.views import SignupAPIView
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [
    path('authproject/login', obtain_auth_token, name = 'authproject-login'),
    path('authproject/signup', SignupAPIView.as_view(), name = 'authproject-signup'),
    # path('authproject/logout')
]
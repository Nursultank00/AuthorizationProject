from django.urls import path
from users.views import SignupAPIView, LoginAPIView, TokenRefreshView
from users.views import LogoutAPIView, VerifyEmailAPIView, ResendVerifyEmailAPIView

urlpatterns = [
    path('login/', LoginAPIView.as_view(), name = 'authproject-login'),
    path('login/refresh/', TokenRefreshView.as_view(), name = 'authproject-login-refresh'),
    path('signup/', SignupAPIView.as_view(), name = 'authproject-signup'),
    path('logout/', LogoutAPIView.as_view(), name = 'authproject-logout'),
    path('email-verify/', VerifyEmailAPIView.as_view(), name = 'authproject-email-verify'),
    path('resend-email/', ResendVerifyEmailAPIView.as_view(), name = 'authproject-resend-email'),
]
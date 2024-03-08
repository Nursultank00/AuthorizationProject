from django.urls import path, include

from users.views import SignupAPIView, LoginAPIView, TokenRefreshView,\
                        LogoutAPIView, VerifyEmailAPIView, ResendVerifyEmailAPIView,\
                        DeleteUserAPIView, ChangePasswordAPIView

urlpatterns = [
    path('login/', LoginAPIView.as_view(), name = 'authproject-login'),
    path('login/refresh/', TokenRefreshView.as_view(), name = 'authproject-login-refresh'),
    path('signup/', SignupAPIView.as_view(), name = 'authproject-signup'),
    path('logout/', LogoutAPIView.as_view(), name = 'authproject-logout'),
    path('email-verify/', VerifyEmailAPIView.as_view(), name = 'authproject-email-verify'),
    path('resend-email/', ResendVerifyEmailAPIView.as_view(), name = 'authproject-resend-email'),
    path('delete-user/', DeleteUserAPIView.as_view(), name = 'authproject-delete'),
    path('change-password/', ChangePasswordAPIView.as_view(), name = 'authproject-change-password'),
    path('password-reset/', include('django_rest_passwordreset.urls'), name='password_reset'),
]
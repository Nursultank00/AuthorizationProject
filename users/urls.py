from django.urls import path
from users.views import SignupAPIView, LoginAPIView, TokenRefreshView, LogoutAPIView

urlpatterns = [
    path('login/', LoginAPIView.as_view(), name = 'authproject-login'),
    path('login/refresh/', TokenRefreshView.as_view(), name = 'authproject-login-refresh'),
    path('signup/', SignupAPIView.as_view(), name = 'authproject-signup'),
    path('logout/', LogoutAPIView.as_view(), name = 'authporject-logout')
]
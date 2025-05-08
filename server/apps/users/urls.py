from django.urls import path
from .views import RegisterView, CustomTokenObtainPairView, ProfileView
from rest_framework_simplejwt.views import TokenRefreshView
from .views import ForgetPasswordView, ResetPasswordView


urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', CustomTokenObtainPairView.as_view()),
    path('token/refresh/', TokenRefreshView.as_view()),
    path('profile/', ProfileView.as_view()),
    path('forget-password/', ForgetPasswordView.as_view()),
    path('resest-password/', ResetPasswordView.as_view()),
]
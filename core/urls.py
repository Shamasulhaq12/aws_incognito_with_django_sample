from django.urls import path
from .views import UserRegistrationCognitoView, UserLoginCognitoView, UserVerificationCognitoView, UserResendVerificationCognitoView, UserForgotPasswordCognitoView, UserConfirmForgotPasswordCognitoView,UserResendVerificationCognitoView



urlpatterns = [
    path('register/', UserRegistrationCognitoView.as_view()),
    path('resend/', UserResendVerificationCognitoView.as_view()),
    path('forgot/', UserForgotPasswordCognitoView.as_view()),
    path('confirm/', UserConfirmForgotPasswordCognitoView.as_view()),
    path('login/', UserLoginCognitoView.as_view()),
    path('verify/', UserVerificationCognitoView.as_view()),
]

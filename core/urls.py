from django.urls import path
from .views import UserRegistrationCognitoView, UserLoginCognitoView, UserVerificationCognitoView


urlpatterns = [
    path('register/', UserRegistrationCognitoView.as_view()),
    path('login/', UserLoginCognitoView.as_view()),
    path('verify/', UserVerificationCognitoView.as_view()),
]

from django.urls import path
from .views import UserRegistrationCognitoView, UserLoginCognitoView


urlpatterns = [
    path('register/', UserRegistrationCognitoView.as_view()),
    path('login/', UserLoginCognitoView.as_view()),
]

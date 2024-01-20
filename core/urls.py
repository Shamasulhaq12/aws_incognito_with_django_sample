from django.urls import path
from .views import UserRegistrationCognitoView, LoginCognitoView


urlpatterns = [
    path('register/', UserRegistrationCognitoView.as_view()),
    path('login/', LoginCognitoView.as_view()),
]

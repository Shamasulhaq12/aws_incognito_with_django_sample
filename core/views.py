# myapp/views.py
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
import boto3
from django.conf import settings
from botocore.exceptions import ClientError
from core.utils import verify_and_decode_jwt


User = get_user_model()

class UserRegistrationCognitoView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        password = request.data.get('password')
        email = request.data.get('email')

        if not password or not email:
            return JsonResponse({'error': 'username, password, and email are required'}, status=400)

        # Register user in AWS Cognito
        try:
            cognito_client = boto3.client('cognito-idp', region_name=settings.COGNITO_AWS_REGION)
            cognito_client.sign_up(
                ClientId=settings.COGNITO_APP_CLIENT_ID,
                Username=email,
                Password=password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                    # Add additional user attributes as needed
                ],
            )
        except ClientError as e:
            return Response({'error': f'Error registering user in Cognito: {e.response["Error"]["Message"]}'}, status=400)
        # Create user in Django

        user = User.objects.create_user(email=email, password=password)
        return Response({'success': f'User {user.email} created successfully'}, status=201)


class UserLoginCognitoView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return JsonResponse({'error': 'username and password are required'}, status=400)

        # Authenticate user in AWS Cognito
        try:
            cognito_client = boto3.client('cognito-idp', region_name=settings.COGNITO_AWS_REGION)
            response = cognito_client.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={'USERNAME': email, 'PASSWORD': password},
                ClientId=settings.COGNITO_APP_CLIENT_ID,
            )
            id_token = response['AuthenticationResult']['IdToken']
        except ClientError as e:
            return Response({'error': f'Error authenticating user in Cognito: {e.response["Error"]["Message"]}'}, status=400)
        # Verify and decode the JWT using Python JOSE
        decoded_token = verify_and_decode_jwt(id_token)
        User.objects.get_or_create(email=email,defaults={'password':password})

        # You can now use the decoded_token as needed in your application logic

        return Response({'success': 'User logged in successfully',"access_token":decoded_token}, status=200)

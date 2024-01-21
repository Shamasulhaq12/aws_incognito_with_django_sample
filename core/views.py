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
import hmac
import hashlib
from django.shortcuts import get_object_or_404
import base64


User = get_user_model()

class UserRegistrationCognitoView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        password = request.data.get('password')
        email = request.data.get('email')

        if not password or not email:
            return JsonResponse({'error': 'username, password, and email are required'}, status=400)
        client_id = settings.COGNITO_APP_CLIENT_ID
        client_secret = settings.COGNITO_APP_CLIENT_SECRET  # Replace with your actual client secret
        message = email + client_id
        secret_hash = hmac.new(str.encode(client_secret), msg=str.encode(message), digestmod=hashlib.sha256).digest()
        secret_hash = base64.b64encode(secret_hash).decode()

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
                SecretHash=secret_hash,
            )
            User.objects.get_or_create(email=email,defaults={'password':password})
            return JsonResponse({'message': 'User registered successfully. Check your email for verification code.'},
                                status=201)
        except ClientError as e:
            return JsonResponse({'error': f'Error registering user in Cognito: {e.response["Error"]["Message"]}'},status=400)


class UserVerificationCognitoView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        verification_code = request.data.get('verification_code')

        if not email or not verification_code:
            return JsonResponse({'error': 'email and verification_code are required'}, status=400)
        client_id = settings.COGNITO_APP_CLIENT_ID
        client_secret = settings.COGNITO_APP_CLIENT_SECRET  # Replace with your actual client secret
        message = email + client_id
        secret_hash = hmac.new(str.encode(client_secret), msg=str.encode(message), digestmod=hashlib.sha256).digest()
        secret_hash = base64.b64encode(secret_hash).decode()
        # Verify user in AWS Cognito
        try:
            cognito_client = boto3.client('cognito-idp', region_name=settings.COGNITO_AWS_REGION)
            cognito_client.confirm_sign_up(
                ClientId=client_id,
                Username=email,
                ConfirmationCode=verification_code,
                SecretHash=secret_hash,
            )
            user = get_object_or_404(User,email=email)
            user.is_active=True
            user.save()
            return JsonResponse({'message': 'User verified successfully'}, status=200)
        except ClientError as e:
            return JsonResponse({'error': f'Error verifying user in Cognito: {e.response["Error"]["Message"]}'},
                                status=400)


class UserLoginCognitoView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return JsonResponse({'error': 'username and password are required'}, status=400)
        client_id = settings.COGNITO_APP_CLIENT_ID
        client_secret = settings.COGNITO_APP_CLIENT_SECRET  # Replace with your actual client secret
        message = email + client_id
        secret_hash = hmac.new(str.encode(client_secret), msg=str.encode(message), digestmod=hashlib.sha256).digest()
        secret_hash = base64.b64encode(secret_hash).decode()
        # Authenticate user in AWS Cognito
        try:
            cognito_client = boto3.client('cognito-idp', region_name=settings.COGNITO_AWS_REGION)
            response = cognito_client.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': password,
                    'SECRET_HASH': secret_hash,  # Include SECRET_HASH in the request
                },
                ClientId=client_id,
            )
            id_token = response['AuthenticationResult']['IdToken']
        except ClientError as e:
            return Response({'error': f'Error authenticating user in Cognito: {e.response["Error"]["Message"]}'}, status=400)
        # Verify and decode the JWT using Python JOSE
        decoded_token = verify_and_decode_jwt(id_token)
        User.objects.get_or_create(email=email,defaults={'password':password})

        # You can now use the decoded_token as needed in your application logic

        return Response({'success': 'User logged in successfully',"access_token":decoded_token}, status=200)

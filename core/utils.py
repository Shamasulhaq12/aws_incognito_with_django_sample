from django.http import JsonResponse
from jose import jwt
from django.conf import settings
import requests
def verify_and_decode_jwt(token):
    # Fetch public keys from Cognito (replace 'your-cognito-region' and 'your-user-pool-id')
    jwk_url = f'https://cognito-idp.{settings.COGNITO_AWS_REGION}.amazonaws.com/{settings.COGNITO_USER_POOL_ID}/.well-known/jwks.json'
    jwks = requests.get(jwk_url).json()['keys']

    for key in jwks:
        try:
            # Verify the JWT using the key
            decoded_token = jwt.decode(token, key, algorithms=['RS256'])
            return decoded_token
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Token has expired'}, status=401)
        except jwt.JWTClaimsError:
            return JsonResponse({'error': 'Invalid token claims'}, status=401)
        except jwt.JWTError:
            continue

    return JsonResponse({'error': 'Unable to verify token'}, status=401)
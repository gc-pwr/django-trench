from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from trench.settings import trench_settings, JWT_ACCESS_COOKIE_NAME


class JWTCookieAuthentication(JWTAuthentication):
    """
    Authentication class that reads JWT access tokens from HTTPOnly cookies.
    Falls back to Authorization header if cookie is not present.

    This allows for maximum security by storing tokens in HTTPOnly cookies
    while maintaining backward compatibility with Authorization headers.
    """

    def authenticate(self, request):
        # Try cookie first
        cookie_name = trench_settings.get(JWT_ACCESS_COOKIE_NAME, 'access_token')
        raw_token = request.COOKIES.get(cookie_name)

        if raw_token:
            try:
                # Validate the token using SimpleJWT's built-in validation
                validated_token = self.get_validated_token(raw_token)
                user = self.get_user(validated_token)
                return (user, validated_token)
            except TokenError as e:
                # Invalid or expired token in cookie
                # Raise AuthenticationFailed to return 401 instead of 403
                # This triggers refresh flow in frontend interceptors
                raise AuthenticationFailed('Invalid or expired token')

        # Fall back to Authorization header
        return super().authenticate(request)

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return 'Bearer'
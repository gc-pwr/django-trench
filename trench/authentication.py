from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from trench.settings import trench_settings, JWT_ACCESS_COOKIE_NAME, JWT_REFRESH_COOKIE_NAME


class JWTCookieAuthentication(JWTAuthentication):
    """
    Authentication class that reads JWT access tokens from HTTPOnly cookies.
    Falls back to Authorization header if cookie is not present.

    This allows for maximum security by storing tokens in HTTPOnly cookies
    while maintaining backward compatibility with Authorization headers.
    """

    def authenticate(self, request):
        # Try cookie first
        cookie_name = trench_settings[JWT_ACCESS_COOKIE_NAME]
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

        # If no access token cookie, check if user has refresh token cookie
        # This means they're using cookie-based auth and access token expired
        refresh_cookie_name = trench_settings[JWT_REFRESH_COOKIE_NAME]
        if request.COOKIES.get(refresh_cookie_name):
            # Allow refresh and logout endpoints to work without access token
            # Check common endpoint paths
            path = request.path
            if '/refresh' in path or '/token/refresh' in path or '/logout' in path:
                # These endpoints should work with just refresh token
                return None

            # User is authenticated with cookies but access token missing/expired
            # Return 401 to trigger frontend refresh flow
            raise AuthenticationFailed('Access token missing or expired')

        # Fall back to Authorization header
        return super().authenticate(request)

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return 'Bearer'
import logging

from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from trench.settings import trench_settings, JWT_ACCESS_COOKIE_NAME

logger = logging.getLogger(__name__)


class JWTCookieAuthentication(JWTAuthentication):
    """
    Authentication class that reads JWT access tokens from HTTPOnly cookies.
    Falls back to Authorization header if cookie is not present.

    Contract:
      * valid access cookie           -> (user, validated_token)
      * invalid/expired access cookie -> treated as NO credentials: falls
        through to the Authorization-header behavior (usually None).
        Cookies are ambient credentials the browser attaches to every
        request, so a stale cookie must not hard-fail anonymous-capable
        endpoints (login, refresh, logout, password reset). Protected
        endpoints still respond 401 - with no successful authenticator,
        IsAuthenticated raises NotAuthenticated and authenticate_header()
        returning "Bearer" makes DRF render it as 401, which is what
        triggers the SPA token-refresh flow.
      * no cookie                     -> plain SimpleJWT header behavior
        (a present-but-invalid header still raises InvalidToken -> 401).
    """

    def authenticate(self, request):
        raw_token = request.COOKIES.get(trench_settings[JWT_ACCESS_COOKIE_NAME])
        if raw_token:
            try:
                validated_token = self.get_validated_token(raw_token)
                return self.get_user(validated_token), validated_token
            except (InvalidToken, TokenError, AuthenticationFailed):
                # Expired/invalid cookie, or the token's user is gone or
                # inactive: degrade to anonymous instead of hard-failing.
                logger.debug("Ignoring invalid JWT access cookie")

        # Fall back to Authorization header
        return super().authenticate(request)

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return "Bearer"

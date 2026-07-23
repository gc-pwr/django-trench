from django.utils import timezone
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_204_NO_CONTENT
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from trench.settings import trench_settings, JWT_REFRESH_COOKIE_NAME, JWT_REFRESH_COOKIE_SECURE, JWT_REFRESH_COOKIE_HTTPONLY, JWT_REFRESH_COOKIE_SAMESITE, JWT_REFRESH_COOKIE_PATH, JWT_REFRESH_COOKIE_DOMAIN, JWT_ROTATE_REFRESH_TOKENS, JWT_ACCESS_COOKIE_NAME, JWT_ACCESS_COOKIE_SECURE, JWT_ACCESS_COOKIE_HTTPONLY, JWT_ACCESS_COOKIE_SAMESITE, JWT_ACCESS_COOKIE_PATH, JWT_ACCESS_COOKIE_DOMAIN, USER_ACTIVE_FIELD
from trench.authentication import JWTCookieAuthentication
from trench.views import MFAFirstStepMixin, MFASecondStepMixin, MFAStepMixin, User
import logging
from rest_framework_simplejwt.settings import api_settings

logger = logging.getLogger("audit_logger")


class MFAJWTView(MFAStepMixin):
    def _successful_authentication_response(self, user: User) -> Response:
        token = RefreshToken.for_user(user=user)
        if trench_settings.UPDATE_LAST_LOGIN:
            user.last_login = timezone.now()
            user.save()

        # Log successful authentication (restore original logging info)
        try:
            # Try to get IP and UserAgent if available
            x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]
            else:
                ip = self.request.META.get('REMOTE_ADDR', 'Unknown')
            agent = self.request.META.get('HTTP_USER_AGENT', 'Unknown')
            logger.info(f"Logon success; UserID: {user.id}; IP: {ip}; UserAgent: {agent};")
        except Exception:
            # Fallback if getting IP/Agent fails
            logger.info(f"Logon success; UserID: {user.id}")

        # Return access token and user data - refresh token goes in HTTPOnly cookie instead of response body
        # Keep the original user serialization that the frontend expects
        try:
            # Try to import the original serializer if available
            from authentication.serializers import UserSerializer
            from core.util import get_employee_id_for_user
            employee_id = get_employee_id_for_user(user)
            user_serialized = UserSerializer(user, context={"employee_id": employee_id}).data
        except ImportError:
            # Fallback if serializer not available in library context
            user_serialized = {
                "id": user.id,
                "username": getattr(user, User.USERNAME_FIELD),
                "email": getattr(user, "email", None),
            }

        data = {
            "access": str(token.access_token),
            "user": user_serialized,
        }

        response = Response(data)

        # Set both tokens as HTTPOnly cookies
        self._set_refresh_token_cookie(response, str(token))
        self._set_access_token_cookie(response, str(token.access_token))

        return response

    def _set_refresh_token_cookie(self, response: Response, refresh_token: str) -> None:
        """Set refresh token as HTTPOnly cookie"""
        self._set_refresh_token_cookie_static(response, refresh_token)

    def _set_access_token_cookie(self, response: Response, access_token: str) -> None:
        """Set access token as HTTPOnly cookie"""
        self._set_access_token_cookie_static(response, access_token)

    @staticmethod
    def _set_refresh_token_cookie_static(response: Response, refresh_token: str) -> None:
        """Set refresh token as HTTPOnly cookie - static method for reuse"""
        cookie_name = trench_settings[JWT_REFRESH_COOKIE_NAME]
        cookie_secure = trench_settings[JWT_REFRESH_COOKIE_SECURE]
        cookie_httponly = trench_settings[JWT_REFRESH_COOKIE_HTTPONLY]
        cookie_samesite = trench_settings[JWT_REFRESH_COOKIE_SAMESITE]
        cookie_path = trench_settings[JWT_REFRESH_COOKIE_PATH]
        cookie_domain = trench_settings[JWT_REFRESH_COOKIE_DOMAIN]

        # Get refresh token lifetime from SimpleJWT settings
        refresh_token_obj = RefreshToken(refresh_token)
        max_age = int(refresh_token_obj.lifetime.total_seconds())

        # Build cookie arguments
        cookie_kwargs = {
            'max_age': max_age,
            'path': cookie_path,
            'secure': cookie_secure,
            'httponly': cookie_httponly,
            'samesite': cookie_samesite,
        }

        # Only set domain if specified
        if cookie_domain:
            cookie_kwargs['domain'] = cookie_domain

        response.set_cookie(
            cookie_name,
            refresh_token,
            **cookie_kwargs
        )

    @staticmethod
    def _set_access_token_cookie_static(response: Response, access_token: str) -> None:
        """Set access token as HTTPOnly cookie - static method for reuse"""
        cookie_name = trench_settings[JWT_ACCESS_COOKIE_NAME]
        cookie_secure = trench_settings[JWT_ACCESS_COOKIE_SECURE]
        cookie_httponly = trench_settings[JWT_ACCESS_COOKIE_HTTPONLY]
        cookie_samesite = trench_settings[JWT_ACCESS_COOKIE_SAMESITE]
        cookie_path = trench_settings[JWT_ACCESS_COOKIE_PATH]
        cookie_domain = trench_settings[JWT_ACCESS_COOKIE_DOMAIN]

        # Get access token lifetime from SimpleJWT settings
        from rest_framework_simplejwt.tokens import AccessToken
        access_token_obj = AccessToken(access_token)
        max_age = int(access_token_obj.lifetime.total_seconds())

        # Build cookie arguments
        cookie_kwargs = {
            'max_age': max_age,
            'path': cookie_path,
            'secure': cookie_secure,
            'httponly': cookie_httponly,
            'samesite': cookie_samesite,
        }

        # Only set domain if specified
        if cookie_domain:
            cookie_kwargs['domain'] = cookie_domain

        response.set_cookie(
            cookie_name,
            access_token,
            **cookie_kwargs
        )

    def finalize_response(self, request, response, *args, **kwargs):
        if response.status_code != 200:
            try:
                # Get IP and UserAgent info like the original
                x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
                if x_forwarded_for:
                    ip = x_forwarded_for.split(',')[0]
                else:
                    ip = request.META.get('REMOTE_ADDR', 'Unknown')
                agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
                email = request.data.get("email", "Unknown")

                logger.warning(
                    f"Login attempt failed; email: {email}; IP: {ip}; UserAgent: {agent}; Status: {response.status_code}; error: {response.data.get('error', '') if response.data else ''}"
                )
            except Exception:
                # Fallback logging if getting IP/Agent fails
                email = request.data.get("email", "Unknown")
                logger.warning(
                    f"Login attempt failed; email: {email}; Status: {response.status_code}; error: {response.data.get('error', '') if response.data else ''}"
                )
        return super().finalize_response(request, response, *args, **kwargs)


class MFAFirstStepJWTView(MFAJWTView, MFAFirstStepMixin):
    pass


class MFASecondStepJWTView(MFAJWTView, MFASecondStepMixin):
    pass


class MFAJWTRefreshView(APIView):
    """
    View to refresh JWT access token using HTTPOnly cookie.

    Response contract (the SPA refresh flow depends on it):
      * 200 {"access": <jwt>} + Set-Cookie for the access token (and the
        rotated refresh token when JWT_ROTATE_REFRESH_TOKENS) whenever the
        refresh token cookie is valid - regardless of the access cookie
        state (present, expired or absent).
      * 401 {"error": ..., "code": "token_not_valid"} ONLY when the refresh
        token is missing/expired/invalid/blacklisted or its user is
        inactive/deleted. A 401 from this endpoint is the single definitive
        "session dead" signal; it is never returned for an expired access
        cookie or transient conditions.

    Authentication and throttling are intentionally disabled: the endpoint
    validates the signed refresh token itself (like SimpleJWT's stock
    TokenRefreshView), and rate limiting a signed-JWT endpoint adds no
    security while shared-IP throttle exhaustion logs whole offices out.
    """
    authentication_classes: list = []
    permission_classes: list = []
    throttle_classes: list = []

    def post(self, request):
        cookie_name = trench_settings[JWT_REFRESH_COOKIE_NAME]
        refresh_token = request.COOKIES.get(cookie_name)

        if not refresh_token:
            return self._invalid_session("Refresh token not found in cookie")

        try:
            refresh = RefreshToken(refresh_token)
        except TokenError:
            return self._invalid_session("Invalid or expired refresh token")

        # In-place rotation makes the session slide indefinitely, so check
        # the user is still active before extending it.
        if not self._user_is_active(refresh):
            return self._invalid_session("User inactive or not found")

        if trench_settings[JWT_ROTATE_REFRESH_TOKENS]:
            # Optional: blacklist old refresh token if configured. Left off
            # by default on purpose: old tokens staying valid until their
            # natural expiry is what lets concurrent tabs refresh without
            # invalidating each other.
            if getattr(api_settings, "BLACKLIST_AFTER_ROTATION", False):
                try:
                    refresh.blacklist()
                except AttributeError:
                    # Blacklist app not installed
                    pass

            # Rotate the refresh token in-place (aligns with SimpleJWT behavior)
            refresh.set_jti()
            refresh.set_exp()
            refresh.set_iat()

        data = {
            "access": str(refresh.access_token),
        }
        response = Response(data, status=HTTP_200_OK)

        if trench_settings[JWT_ROTATE_REFRESH_TOKENS]:
            MFAJWTView._set_refresh_token_cookie_static(response, str(refresh))
        MFAJWTView._set_access_token_cookie_static(response, str(refresh.access_token))
        return response

    @staticmethod
    def _user_is_active(refresh) -> bool:
        try:
            user = User._default_manager.get(
                **{api_settings.USER_ID_FIELD: refresh[api_settings.USER_ID_CLAIM]}
            )
        except User.DoesNotExist:
            return False
        return bool(getattr(user, trench_settings[USER_ACTIVE_FIELD], True))

    @staticmethod
    def _invalid_session(message: str) -> Response:
        return Response(
            {"error": message, "code": "token_not_valid"},
            status=HTTP_401_UNAUTHORIZED,
        )


class MFAJWTLogoutView(APIView):
    """
    View to logout user by clearing both JWT cookies.

    Anonymous-capable and idempotent: always returns 204 and always clears
    the cookies, even when the access token is expired or missing - that is
    exactly the state a session-expiry logout arrives in. Best-effort
    blacklists the presented refresh token so it cannot be replayed for the
    remainder of its lifetime.
    """
    authentication_classes: list = []
    permission_classes: list = []
    throttle_classes: list = []

    def post(self, request):
        refresh_cookie_name = trench_settings[JWT_REFRESH_COOKIE_NAME]
        access_cookie_name = trench_settings[JWT_ACCESS_COOKIE_NAME]

        # The access token may be expired, so derive the user id for the
        # audit log from the (signed) refresh token when needed.
        user_id = getattr(request.user, "id", None)
        raw_refresh = request.COOKIES.get(refresh_cookie_name)
        if raw_refresh:
            try:
                token = RefreshToken(raw_refresh)
                if user_id is None:
                    user_id = token.get(api_settings.USER_ID_CLAIM)
                try:
                    token.blacklist()
                except AttributeError:
                    # Blacklist app not installed
                    pass
            except TokenError:
                # Already expired/invalid: nothing to revoke
                pass

        # A 204 must not carry a body
        response = Response(status=HTTP_204_NO_CONTENT)

        # Deletion only takes effect when path/domain/samesite match the
        # attributes the cookies were set with.
        for name, path_key, domain_key, samesite_key in (
            (
                refresh_cookie_name,
                JWT_REFRESH_COOKIE_PATH,
                JWT_REFRESH_COOKIE_DOMAIN,
                JWT_REFRESH_COOKIE_SAMESITE,
            ),
            (
                access_cookie_name,
                JWT_ACCESS_COOKIE_PATH,
                JWT_ACCESS_COOKIE_DOMAIN,
                JWT_ACCESS_COOKIE_SAMESITE,
            ),
        ):
            delete_kwargs = {
                "path": trench_settings[path_key],
                "samesite": trench_settings[samesite_key],
            }
            if trench_settings[domain_key]:
                delete_kwargs["domain"] = trench_settings[domain_key]
            response.delete_cookie(name, **delete_kwargs)

        # Log the logout
        logger.info(
            f"Logout success; UserID: {user_id if user_id is not None else 'anonymous'}"
        )

        return response


class MFAJWTVerifyView(APIView):
    permission_classes = []
    authentication_classes = [JWTCookieAuthentication]

    def get(self, request):
        # If we get here, authentication succeeded
        if request.user and request.user.is_authenticated:
            return Response({"valid": True, "user_id": request.user.id})
        return Response({"valid": False}, status=401)

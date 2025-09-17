from django.http import JsonResponse
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_204_NO_CONTENT
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from trench.settings import trench_settings, JWT_REFRESH_COOKIE_NAME, JWT_REFRESH_COOKIE_SECURE, JWT_REFRESH_COOKIE_HTTPONLY, JWT_REFRESH_COOKIE_SAMESITE, JWT_REFRESH_COOKIE_PATH, JWT_REFRESH_COOKIE_DOMAIN, JWT_ROTATE_REFRESH_TOKENS
from trench.views import MFAFirstStepMixin, MFASecondStepMixin, MFAStepMixin, User
import logging

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
            user_serialized = UserSerializer(user).data
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

        # Set refresh token as HTTPOnly cookie
        self._set_refresh_token_cookie(response, str(token))

        return response

    def _set_refresh_token_cookie(self, response: Response, refresh_token: str) -> None:
        """Set refresh token as HTTPOnly cookie"""
        self._set_refresh_token_cookie_static(response, refresh_token)

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
    Takes refresh token from cookie and returns new access token.
    """
    permission_classes = []

    def post(self, request):
        cookie_name = trench_settings[JWT_REFRESH_COOKIE_NAME]
        refresh_token = request.COOKIES.get(cookie_name)

        if not refresh_token:
            return Response(
                {"error": "Refresh token not found in cookie"},
                status=HTTP_401_UNAUTHORIZED
            )

        try:
            refresh = RefreshToken(refresh_token)

            # Check if we should rotate refresh tokens
            if trench_settings[JWT_ROTATE_REFRESH_TOKENS]:
                # Generate new refresh token
                refresh.set_jti()
                refresh.set_exp()

                # Get user for new token
                user = refresh.user
                new_refresh = RefreshToken.for_user(user)

                data = {
                    "access": str(new_refresh.access_token),
                }

                response = Response(data, status=HTTP_200_OK)

                # Set new refresh token cookie using helper method
                MFAJWTView._set_refresh_token_cookie_static(response, str(new_refresh))

                return response
            else:
                # Just generate new access token with existing refresh token
                data = {
                    "access": str(refresh.access_token),
                }
                return Response(data, status=HTTP_200_OK)

        except TokenError as e:
            return Response(
                {"error": "Invalid or expired refresh token"},
                status=HTTP_401_UNAUTHORIZED
            )


class MFAJWTLogoutView(APIView):
    """
    View to logout user by clearing the refresh token cookie.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        cookie_name = trench_settings[JWT_REFRESH_COOKIE_NAME]
        cookie_path = trench_settings[JWT_REFRESH_COOKIE_PATH]
        cookie_domain = trench_settings[JWT_REFRESH_COOKIE_DOMAIN]

        response = Response(
            {"message": "Successfully logged out"},
            status=HTTP_204_NO_CONTENT
        )

        # Clear refresh token cookie - need to match domain if set
        delete_kwargs = {'path': cookie_path}
        if cookie_domain:
            delete_kwargs['domain'] = cookie_domain

        response.delete_cookie(
            cookie_name,
            **delete_kwargs
        )

        # Log the logout
        logger.info(f"Logout success; UserID: {request.user.id}")

        return response

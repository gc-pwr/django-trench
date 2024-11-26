from django.utils import timezone
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.serializers import UserSerializer
from authentication.utils import get_client_ip_agent
from trench.settings import trench_settings
from trench.views import MFAFirstStepMixin, MFASecondStepMixin, MFAStepMixin, User
import logging

logger = logging.getLogger("audit_logger")


class MFAJWTView(MFAStepMixin):
    def _successful_authentication_response(self, user: User) -> Response:
        token = RefreshToken.for_user(user=user)
        if trench_settings.UPDATE_LAST_LOGIN:
            user.last_login = timezone.now()
            user.save()

        ip, agent = get_client_ip_agent(self.request)

        logger.info(f"Logon success; UserID: {user.id}; IP: {ip}; UserAgent: {agent};")

        user_serialized = UserSerializer(user).data
        data = {
            "refresh": str(token),
            "access": str(token.access_token),
            "user": user_serialized,
        }
        return Response(data)

    def finalize_response(self, request, response, *args, **kwargs):
        if response.status_code != 200:
            ip, agent = get_client_ip_agent(request)
            email = request.data.get("email", "Unknown")
            logger.warning(
                "Login attempt failed; email: %s, IP: %s; UserAgent: %s; Status: %s, error: %s".format(
                    email,
                    ip,
                    agent,
                    response.status_code,
                    response.data.get("error", "") if response.data else "",
                )
            )
        return super().finalize_response(request, response, *args, **kwargs)


class MFAFirstStepJWTView(MFAJWTView, MFAFirstStepMixin):
    pass


class MFASecondStepJWTView(MFAJWTView, MFASecondStepMixin):
    pass

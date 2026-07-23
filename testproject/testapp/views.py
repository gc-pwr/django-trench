from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from trench.authentication import JWTCookieAuthentication


class CookieProtectedProbeView(APIView):
    """
    Reproduces the integration of consumer apps that use
    JWTCookieAuthentication as their (default) authenticator on protected
    endpoints. DRF binds DEFAULT_AUTHENTICATION_CLASSES at class-definition
    time, so tests declare the authenticator explicitly here instead of
    overriding REST_FRAMEWORK per-test.
    """

    authentication_classes = [JWTCookieAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"user_id": request.user.id})

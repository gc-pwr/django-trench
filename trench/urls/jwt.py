from django.urls import path

from trench.views.jwt import (
    MFAFirstStepJWTView,
    MFASecondStepJWTView,
    MFAJWTRefreshView,
    MFAJWTLogoutView,
    MFAJWTVerifyView,
)


urlpatterns = (
    path("login/", MFAFirstStepJWTView.as_view(), name="generate-code-jwt"),
    path("login/code/", MFASecondStepJWTView.as_view(), name="generate-token-jwt"),
    path("refresh/", MFAJWTRefreshView.as_view(), name="refresh-token-jwt"),
    path("logout/", MFAJWTLogoutView.as_view(), name="logout-jwt"),
    path("verify/", MFAJWTVerifyView.as_view(), name="verify-token-jwt")
)

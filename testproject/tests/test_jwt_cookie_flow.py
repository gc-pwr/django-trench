import pytest

from django.test import RequestFactory

from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.utils import aware_utcnow

from trench.authentication import JWTCookieAuthentication
from trench.settings import (
    trench_settings,
    JWT_ACCESS_COOKIE_NAME,
    JWT_REFRESH_COOKIE_NAME,
)

from tests.utils import TrenchAPIClient


ACCESS_COOKIE = trench_settings[JWT_ACCESS_COOKIE_NAME]
REFRESH_COOKIE = trench_settings[JWT_REFRESH_COOKIE_NAME]
PATH_REFRESH = TrenchAPIClient.PATH_AUTH_JWT_REFRESH
PATH_LOGOUT = TrenchAPIClient.PATH_AUTH_JWT_LOGOUT
PATH_PROBE = "/probe/"
HEADER_TEMPLATE = "Bearer {}"


def make_refresh(user) -> RefreshToken:
    return RefreshToken.for_user(user)


def make_expired_access(user) -> str:
    access = make_refresh(user).access_token
    access.set_exp(from_time=aware_utcnow() - 2 * api_settings.ACCESS_TOKEN_LIFETIME)
    return str(access)


def make_expired_refresh(user) -> str:
    refresh = make_refresh(user)
    refresh.set_exp(from_time=aware_utcnow() - 2 * api_settings.REFRESH_TOKEN_LIFETIME)
    return str(refresh)


def assert_cookie_deleted(response, cookie_name):
    cookie = response.cookies.get(cookie_name)
    assert cookie is not None, f"no Set-Cookie for {cookie_name}"
    assert cookie.value == ""
    assert cookie["max-age"] == 0


@pytest.mark.django_db
class TestRefreshEndpoint:
    def test_refresh_with_valid_refresh_cookie_only(self, active_user):
        client = TrenchAPIClient()
        old_refresh = str(make_refresh(active_user))
        client.cookies[REFRESH_COOKIE] = old_refresh

        response = client.post(PATH_REFRESH, data={}, format="json")

        assert response.status_code == 200
        assert "access" in response.data
        assert response.cookies[ACCESS_COOKIE].value
        # JWT_ROTATE_REFRESH_TOKENS is on: the refresh cookie must rotate
        assert response.cookies[REFRESH_COOKIE].value
        assert response.cookies[REFRESH_COOKIE].value != old_refresh

    def test_refresh_with_expired_access_cookie_and_valid_refresh(self, active_user):
        """Regression: a present-but-expired access cookie must not 401 the
        refresh endpoint (the endpoint whose job is replacing that token)."""
        client = TrenchAPIClient()
        client.cookies[ACCESS_COOKIE] = make_expired_access(active_user)
        client.cookies[REFRESH_COOKIE] = str(make_refresh(active_user))

        response = client.post(PATH_REFRESH, data={}, format="json")

        assert response.status_code == 200
        assert "access" in response.data

    def test_refresh_without_refresh_cookie(self):
        client = TrenchAPIClient()

        response = client.post(PATH_REFRESH, data={}, format="json")

        assert response.status_code == 401
        assert response.data["code"] == "token_not_valid"

    def test_refresh_with_expired_refresh_cookie(self, active_user):
        client = TrenchAPIClient()
        client.cookies[REFRESH_COOKIE] = make_expired_refresh(active_user)

        response = client.post(PATH_REFRESH, data={}, format="json")

        assert response.status_code == 401
        assert response.data["code"] == "token_not_valid"

    def test_refresh_with_blacklisted_refresh_token(self, active_user):
        client = TrenchAPIClient()
        refresh = make_refresh(active_user)
        refresh.blacklist()
        client.cookies[REFRESH_COOKIE] = str(refresh)

        response = client.post(PATH_REFRESH, data={}, format="json")

        assert response.status_code == 401
        assert response.data["code"] == "token_not_valid"

    def test_refresh_with_deactivated_user(self, active_user):
        """In-place rotation slides the session forever, so refresh must
        stop honoring tokens of users deactivated after token issuance."""
        client = TrenchAPIClient()
        client.cookies[REFRESH_COOKIE] = str(make_refresh(active_user))
        active_user.is_active = False
        active_user.save()

        response = client.post(PATH_REFRESH, data={}, format="json")

        assert response.status_code == 401
        assert response.data["code"] == "token_not_valid"

    def test_refresh_with_deleted_user(self, active_user):
        client = TrenchAPIClient()
        client.cookies[REFRESH_COOKIE] = str(make_refresh(active_user))
        active_user.delete()

        response = client.post(PATH_REFRESH, data={}, format="json")

        assert response.status_code == 401

    def test_old_refresh_token_still_valid_after_rotation(self, active_user):
        """Documents the multi-tab grace semantics: rotation does NOT
        blacklist the previous token (BLACKLIST_AFTER_ROTATION off), so a
        concurrent tab holding the pre-rotation cookie can still refresh."""
        client = TrenchAPIClient()
        old_refresh = str(make_refresh(active_user))
        client.cookies[REFRESH_COOKIE] = old_refresh

        first = client.post(PATH_REFRESH, data={}, format="json")
        assert first.status_code == 200

        # Replay the pre-rotation token, as a second tab would
        client.cookies[REFRESH_COOKIE] = old_refresh
        second = client.post(PATH_REFRESH, data={}, format="json")
        assert second.status_code == 200


@pytest.mark.django_db
class TestLogoutEndpoint:
    def test_logout_with_valid_cookies(self, active_user):
        client = TrenchAPIClient()
        refresh = make_refresh(active_user)
        client.cookies[ACCESS_COOKIE] = str(refresh.access_token)
        client.cookies[REFRESH_COOKIE] = str(refresh)

        response = client.post(PATH_LOGOUT, data={}, format="json")

        assert response.status_code == 204
        assert_cookie_deleted(response, REFRESH_COOKIE)
        assert_cookie_deleted(response, ACCESS_COOKIE)

        # The presented refresh token is blacklisted: replaying it fails
        replay = TrenchAPIClient()
        replay.cookies[REFRESH_COOKIE] = str(refresh)
        assert replay.post(PATH_REFRESH, data={}, format="json").status_code == 401

    def test_logout_with_expired_access_and_valid_refresh(self, active_user):
        """Regression: session-expiry logout arrives with an expired access
        cookie - it must still clear the cookies (previously 401ed and the
        HttpOnly refresh cookie survived for up to its full lifetime)."""
        client = TrenchAPIClient()
        client.cookies[ACCESS_COOKIE] = make_expired_access(active_user)
        client.cookies[REFRESH_COOKIE] = str(make_refresh(active_user))

        response = client.post(PATH_LOGOUT, data={}, format="json")

        assert response.status_code == 204
        assert_cookie_deleted(response, REFRESH_COOKIE)
        assert_cookie_deleted(response, ACCESS_COOKIE)

    def test_logout_with_no_cookies_is_idempotent(self):
        client = TrenchAPIClient()

        response = client.post(PATH_LOGOUT, data={}, format="json")

        assert response.status_code == 204
        assert_cookie_deleted(response, REFRESH_COOKIE)
        assert_cookie_deleted(response, ACCESS_COOKIE)


@pytest.mark.django_db
class TestCookieAuthentication:
    def test_probe_with_valid_access_cookie(self, active_user):
        client = TrenchAPIClient()
        client.cookies[ACCESS_COOKIE] = str(make_refresh(active_user).access_token)

        response = client.get(PATH_PROBE)

        assert response.status_code == 200
        assert response.data["user_id"] == active_user.id

    def test_probe_with_expired_access_cookie(self, active_user):
        """Pins the SPA refresh trigger: expired cookie on a protected
        endpoint must yield 401 (not 403) with a WWW-Authenticate header."""
        client = TrenchAPIClient()
        client.cookies[ACCESS_COOKIE] = make_expired_access(active_user)

        response = client.get(PATH_PROBE)

        assert response.status_code == 401
        assert response["WWW-Authenticate"] == "Bearer"

    def test_probe_without_credentials(self):
        client = TrenchAPIClient()

        response = client.get(PATH_PROBE)

        assert response.status_code == 401

    def test_stale_cookie_with_valid_header_falls_back(self, active_user):
        """An invalid ambient cookie must not block header-authenticated
        clients: the authenticator degrades to the Authorization header."""
        client = TrenchAPIClient()
        client.cookies[ACCESS_COOKIE] = make_expired_access(active_user)
        valid_access = str(make_refresh(active_user).access_token)
        client.credentials(HTTP_AUTHORIZATION=HEADER_TEMPLATE.format(valid_access))

        response = client.get(PATH_PROBE)

        assert response.status_code == 200
        assert response.data["user_id"] == active_user.id

    def test_header_fallback_still_works(self, active_user):
        client = TrenchAPIClient()
        valid_access = str(make_refresh(active_user).access_token)
        client.credentials(HTTP_AUTHORIZATION=HEADER_TEMPLATE.format(valid_access))

        response = client.get(PATH_PROBE)

        assert response.status_code == 200

    def test_authenticator_treats_stale_cookie_as_no_credentials(self, active_user):
        """Unit-level pin of the contract: an expired access cookie is NO
        credentials - authenticate() returns None instead of raising, so
        anonymous-capable endpoints (login, refresh, password reset) keep
        working when a stale cookie rides along."""
        request = RequestFactory().get("/any/endpoint/")
        request.COOKIES[ACCESS_COOKIE] = make_expired_access(active_user)

        assert JWTCookieAuthentication().authenticate(request) is None

    def test_full_login_refresh_logout_cycle(self, active_user):
        """End-to-end: login (no MFA) -> cookies set -> refresh via cookie
        only -> logout clears everything."""
        client = TrenchAPIClient()
        login = client.authenticate(user=active_user)
        assert login.status_code == 200
        assert ACCESS_COOKIE in client.cookies
        assert REFRESH_COOKIE in client.cookies

        # Drop the Authorization header the helper set, so this exercises
        # the cookie path exclusively.
        client.credentials()

        refreshed = client.post(PATH_REFRESH, data={}, format="json")
        assert refreshed.status_code == 200

        logout = client.post(PATH_LOGOUT, data={}, format="json")
        assert logout.status_code == 204

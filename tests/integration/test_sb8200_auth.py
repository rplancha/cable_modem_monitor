"""Integration tests for SB8200 authentication using mock server.

These tests verify the parser works correctly with both firmware variants:
- Tim's variant: HTTP, no auth required (older firmware)
- Travis's variant: HTTPS, URL-based auth (firmware 1.01.009.47+)

TDD approach: Tests written first, implementation follows.
"""

import requests

from custom_components.cable_modem_monitor.parsers.arris.sb8200 import ArrisSB8200Parser


class TestSB8200AuthNoAuthServer:
    """Test SB8200 parser with no-auth server (Tim's variant)."""

    def test_login_no_credentials_succeeds(self, sb8200_server_noauth):
        """Test login succeeds on no-auth server without credentials."""
        parser = ArrisSB8200Parser()
        session = requests.Session()

        success, error = parser.login(session, sb8200_server_noauth.url, None, None)

        assert success is True
        assert error is None

    def test_login_with_credentials_still_succeeds(self, sb8200_server_noauth):
        """Test login succeeds on no-auth server even with credentials provided.

        Note: With credentials, login() may return HTML content on success (not None).
        """
        parser = ArrisSB8200Parser()
        session = requests.Session()

        success, html_or_error = parser.login(session, sb8200_server_noauth.url, "admin", "password")

        assert success is True
        # With credentials, returns HTML on success (not error)
        if html_or_error is not None:
            assert isinstance(html_or_error, str)


class TestSB8200AuthServer:
    """Test SB8200 parser with auth server (Travis's variant)."""

    def test_login_with_valid_credentials_succeeds(self, sb8200_server_auth):
        """Test login succeeds on auth server with valid credentials.

        Note: With credentials, login() may return HTML content on success (not None).
        """
        parser = ArrisSB8200Parser()
        session = requests.Session()

        success, html_or_error = parser.login(session, sb8200_server_auth.url, "admin", "password")

        assert success is True
        # With credentials, returns HTML on success (not error)
        if html_or_error is not None:
            assert isinstance(html_or_error, str)

    def test_login_with_invalid_credentials_fails(self, sb8200_server_auth):
        """Test login fails on auth server with invalid credentials."""
        parser = ArrisSB8200Parser()
        session = requests.Session()

        success, error = parser.login(session, sb8200_server_auth.url, "admin", "wrongpassword")

        assert success is False
        assert error is not None

    def test_login_without_credentials_succeeds_for_detection(self, sb8200_server_auth):
        """Test login without credentials succeeds (for detection phase).

        The parser should return success even without credentials so that
        model detection can work. The actual data fetch will fail later.
        """
        parser = ArrisSB8200Parser()
        session = requests.Session()

        success, error = parser.login(session, sb8200_server_auth.url, None, None)

        # Should succeed for detection to work
        assert success is True


class TestSB8200AuthHTTPS:
    """Test SB8200 parser with HTTPS + auth (full Travis scenario)."""

    def test_login_over_https_with_valid_credentials(self, sb8200_server_auth_https):
        """Test authentication works over HTTPS with self-signed cert.

        Note: With credentials, login() may return HTML content on success (not None).
        """
        parser = ArrisSB8200Parser()
        session = requests.Session()
        session.verify = False  # Allow self-signed cert

        success, html_or_error = parser.login(session, sb8200_server_auth_https.url, "admin", "password")

        assert success is True
        # With credentials, returns HTML on success (not error)
        if html_or_error is not None:
            assert isinstance(html_or_error, str)

    def test_login_over_https_with_invalid_credentials(self, sb8200_server_auth_https):
        """Test auth failure over HTTPS."""
        parser = ArrisSB8200Parser()
        session = requests.Session()
        session.verify = False

        success, error = parser.login(session, sb8200_server_auth_https.url, "admin", "badpassword")

        assert success is False
        assert error is not None


class TestSB8200AuthDataFetch:
    """Test that authenticated sessions can fetch data."""

    def test_fetch_status_page_after_auth(self, sb8200_server_auth):
        """Test fetching status page works after authentication."""
        import base64

        parser = ArrisSB8200Parser()
        session = requests.Session()

        # First authenticate
        success, error = parser.login(session, sb8200_server_auth.url, "admin", "password")
        assert success is True

        # The login should set up the session to fetch authenticated pages
        # Build the auth URL manually to verify the mechanism works
        token = base64.b64encode(b"admin:password").decode()
        auth_url = f"{sb8200_server_auth.url}/cmconnectionstatus.html?login_{token}"

        response = session.get(auth_url)
        assert response.status_code == 200
        assert "Downstream" in response.text

    def test_fetch_status_page_without_auth_fails(self, sb8200_server_auth):
        """Test fetching status page without auth returns 401."""
        session = requests.Session()

        response = session.get(f"{sb8200_server_auth.url}/cmconnectionstatus.html")

        assert response.status_code == 401

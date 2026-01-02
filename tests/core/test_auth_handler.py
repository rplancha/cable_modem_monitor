"""Tests for the AuthHandler class.

This tests the runtime authentication handler that applies stored
authentication strategies during polling.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from custom_components.cable_modem_monitor.core.auth.handler import AuthHandler
from custom_components.cable_modem_monitor.core.auth.types import AuthStrategyType


class TestAuthHandlerInit:
    """Test AuthHandler initialization."""

    def test_init_with_string_strategy(self):
        """Test initialization with string strategy."""
        handler = AuthHandler(strategy="basic_http")
        assert handler.strategy == AuthStrategyType.BASIC_HTTP

    def test_init_with_enum_strategy(self):
        """Test initialization with enum strategy."""
        handler = AuthHandler(strategy=AuthStrategyType.FORM_PLAIN)
        assert handler.strategy == AuthStrategyType.FORM_PLAIN

    def test_init_with_none_strategy(self):
        """Test initialization with None strategy."""
        handler = AuthHandler(strategy=None)
        assert handler.strategy == AuthStrategyType.UNKNOWN

    def test_init_with_unknown_string(self):
        """Test initialization with unknown string defaults to UNKNOWN."""
        handler = AuthHandler(strategy="not_a_real_strategy")
        assert handler.strategy == AuthStrategyType.UNKNOWN

    def test_init_with_uppercase_string(self):
        """Test initialization with uppercase string (case-insensitive matching)."""
        # Config entries may store uppercase strategy names
        handler = AuthHandler(strategy="FORM_BASE64")
        assert handler.strategy == AuthStrategyType.FORM_BASE64

        handler2 = AuthHandler(strategy="BASIC_HTTP")
        assert handler2.strategy == AuthStrategyType.BASIC_HTTP

    def test_init_with_form_config(self):
        """Test initialization with form config."""
        form_config = {
            "action": "/login",
            "method": "POST",
            "username_field": "user",
            "password_field": "pass",
        }
        handler = AuthHandler(strategy="form_plain", form_config=form_config)
        assert handler.form_config == form_config


class TestAuthHandlerNoAuth:
    """Test NO_AUTH strategy."""

    def test_no_auth_succeeds_without_credentials(self):
        """Test NO_AUTH strategy succeeds."""
        handler = AuthHandler(strategy=AuthStrategyType.NO_AUTH)
        session = MagicMock()

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username=None,
            password=None,
        )

        assert success is True
        assert html is None


class TestAuthHandlerBasicAuth:
    """Test BASIC_HTTP strategy."""

    def test_basic_auth_sets_session_auth(self):
        """Test Basic Auth sets session.auth."""
        handler = AuthHandler(strategy=AuthStrategyType.BASIC_HTTP)
        session = MagicMock()
        response = MagicMock()
        response.status_code = 200
        response.text = "<html>Status Page</html>"
        session.get.return_value = response

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username="admin",
            password="password",
        )

        assert success is True
        assert session.auth == ("admin", "password")
        assert html == "<html>Status Page</html>"

    def test_basic_auth_fails_without_credentials(self):
        """Test Basic Auth fails without credentials."""
        handler = AuthHandler(strategy=AuthStrategyType.BASIC_HTTP)
        session = MagicMock()

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username=None,
            password=None,
        )

        assert success is False
        assert html is None

    def test_basic_auth_fails_on_401(self):
        """Test Basic Auth fails on 401 response."""
        handler = AuthHandler(strategy=AuthStrategyType.BASIC_HTTP)
        session = MagicMock()
        response = MagicMock()
        response.status_code = 401
        session.get.return_value = response

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username="admin",
            password="wrong",
        )

        assert success is False
        assert session.auth is None  # Should be cleared on failure

    def test_basic_auth_handles_exception(self):
        """Test Basic Auth handles connection exception."""
        handler = AuthHandler(strategy=AuthStrategyType.BASIC_HTTP)
        session = MagicMock()
        session.get.side_effect = Exception("Connection refused")

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username="admin",
            password="password",
        )

        assert success is False
        assert html is None


class TestAuthHandlerFormAuth:
    """Test FORM_PLAIN strategy."""

    def test_form_auth_submits_form(self):
        """Test form auth submits form data."""
        form_config = {
            "action": "/login",
            "method": "POST",
            "username_field": "user",
            "password_field": "pass",
            "hidden_fields": {"csrf": "token123"},
        }
        handler = AuthHandler(strategy=AuthStrategyType.FORM_PLAIN, form_config=form_config)
        session = MagicMock()

        # Mock post response (after form submission)
        post_response = MagicMock()
        post_response.status_code = 302
        post_response.text = "<html>Redirecting...</html>"

        # Mock get response (fetching data page)
        get_response = MagicMock()
        get_response.status_code = 200
        get_response.text = "<html>Status Page</html>"

        session.post.return_value = post_response
        session.get.return_value = get_response

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username="admin",
            password="password",
        )

        assert success is True
        assert html == "<html>Status Page</html>"

        # Verify form was submitted correctly
        session.post.assert_called_once()
        call_args = session.post.call_args
        assert call_args[0][0] == "http://192.168.100.1/login"
        assert call_args[1]["data"]["user"] == "admin"
        assert call_args[1]["data"]["pass"] == "password"
        assert call_args[1]["data"]["csrf"] == "token123"

    def test_form_auth_fails_without_credentials(self):
        """Test form auth fails without credentials."""
        form_config = {
            "action": "/login",
            "method": "POST",
            "username_field": "user",
            "password_field": "pass",
        }
        handler = AuthHandler(strategy=AuthStrategyType.FORM_PLAIN, form_config=form_config)
        session = MagicMock()

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username=None,
            password=None,
        )

        assert success is False
        assert html is None

    def test_form_auth_fails_without_form_config(self):
        """Test form auth fails without form config."""
        handler = AuthHandler(strategy=AuthStrategyType.FORM_PLAIN, form_config=None)
        session = MagicMock()

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username="admin",
            password="password",
        )

        assert success is False
        assert html is None

    def test_form_auth_detects_login_page_failure(self):
        """Test form auth detects when still on login page."""
        form_config = {
            "action": "/login",
            "method": "POST",
            "username_field": "user",
            "password_field": "pass",
        }
        handler = AuthHandler(strategy=AuthStrategyType.FORM_PLAIN, form_config=form_config)
        session = MagicMock()

        # Post returns login page again (wrong credentials)
        post_response = MagicMock()
        post_response.status_code = 200
        post_response.text = '<html><form><input type="password" name="pass"></form></html>'
        session.post.return_value = post_response

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username="admin",
            password="wrong",
        )

        assert success is False
        assert html is None

    def test_form_auth_uses_get_method(self):
        """Test form auth uses GET when method is GET."""
        form_config = {
            "action": "/auth",
            "method": "GET",
            "username_field": "user",
            "password_field": "pass",
        }
        handler = AuthHandler(strategy=AuthStrategyType.FORM_PLAIN, form_config=form_config)
        session = MagicMock()

        get_response = MagicMock()
        get_response.status_code = 200
        get_response.text = "<html>Status Page</html>"
        session.get.return_value = get_response

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username="admin",
            password="password",
        )

        assert success is True
        session.get.assert_called()

    def test_form_auth_base64_encodes_password(self):
        """Test FORM_BASE64 strategy base64-encodes the password."""
        import base64

        form_config = {
            "action": "/goform/login",
            "method": "POST",
            "username_field": "loginUsername",
            "password_field": "loginPassword",
        }
        handler = AuthHandler(strategy=AuthStrategyType.FORM_BASE64, form_config=form_config)
        session = MagicMock()

        # Mock post response
        post_response = MagicMock()
        post_response.status_code = 200
        post_response.text = "<html>Success</html>"

        # Mock get response
        get_response = MagicMock()
        get_response.status_code = 200
        get_response.text = "<html>Status Page</html>"

        session.post.return_value = post_response
        session.get.return_value = get_response

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username="admin",
            password="mypassword",
        )

        assert success is True

        # Verify password was base64-encoded in the form data
        call_args = session.post.call_args
        form_data = call_args[1]["data"]
        expected_encoded = base64.b64encode(b"mypassword").decode("utf-8")
        assert form_data["loginPassword"] == expected_encoded
        assert form_data["loginUsername"] == "admin"


class TestAuthHandlerHNAP:
    """Test HNAP_SESSION strategy."""

    def test_hnap_auth_no_credentials(self):
        """Test HNAP strategy returns False without credentials."""
        handler = AuthHandler(strategy=AuthStrategyType.HNAP_SESSION)
        session = MagicMock()

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username=None,
            password=None,
        )

        # HNAP without credentials should fail
        assert success is False
        assert html is None

    def test_hnap_auth_with_credentials(self):
        """Test HNAP strategy authenticates using HNAPJsonRequestBuilder."""
        handler = AuthHandler(
            strategy=AuthStrategyType.HNAP_SESSION,
            hnap_config={
                "endpoint": "/HNAP1/",
                "namespace": "http://purenetworks.com/HNAP1/",
            },
        )

        # Mock the session to simulate HNAP login
        session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = (
            '{"LoginResponse": {"LoginResult": "OK", "Challenge": "abc", ' '"Cookie": "xyz", "PublicKey": "123"}}'
        )
        session.post.return_value = mock_response

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username="admin",
            password="password",
        )

        # With proper mock setup, HNAP should succeed
        assert session.post.called
        # Note: Full HNAP flow requires multiple requests, this tests the handler calls the builder


class TestAuthHandlerURLToken:
    """Test URL_TOKEN_SESSION strategy."""

    def test_url_token_auth_no_credentials(self):
        """Test URL token strategy skips auth without credentials."""
        handler = AuthHandler(strategy=AuthStrategyType.URL_TOKEN_SESSION)
        session = MagicMock()

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username=None,
            password=None,
        )

        # URL token without credentials should succeed (skip auth)
        assert success is True
        assert html is None

    def test_url_token_auth_with_credentials(self):
        """Test URL token strategy authenticates with credentials."""
        handler = AuthHandler(
            strategy=AuthStrategyType.URL_TOKEN_SESSION,
            url_token_config={
                "login_page": "/cmconnectionstatus.html",
                "login_prefix": "login_",
                "session_cookie_name": "credential",
                "data_page": "/cmconnectionstatus.html",
                "token_prefix": "ct_",
                "success_indicator": "Downstream",
            },
        )

        # Mock successful login response
        session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>Downstream Channels</html>"
        session.get.return_value = mock_response

        success, html = handler.authenticate(
            session=session,
            base_url="https://192.168.100.1",
            username="admin",
            password="password",
        )

        # Should make GET request with token in URL
        assert session.get.called
        assert success is True


class TestAuthHandlerUnknown:
    """Test UNKNOWN strategy."""

    def test_unknown_returns_true_for_fallback(self):
        """Test unknown strategy returns True to allow fallback."""
        handler = AuthHandler(strategy=AuthStrategyType.UNKNOWN)
        session = MagicMock()

        success, html = handler.authenticate(
            session=session,
            base_url="http://192.168.100.1",
            username="admin",
            password="password",
        )

        # Unknown should return True to allow parser fallback
        assert success is True
        assert html is None


class TestURLResolution:
    """Test URL resolution helper."""

    def test_resolve_relative_url(self):
        """Test resolving relative URL."""
        handler = AuthHandler(strategy=AuthStrategyType.FORM_PLAIN)
        result = handler._resolve_url("http://192.168.100.1", "/login")
        assert result == "http://192.168.100.1/login"

    def test_resolve_absolute_url(self):
        """Test absolute URLs are unchanged."""
        handler = AuthHandler(strategy=AuthStrategyType.FORM_PLAIN)
        result = handler._resolve_url("http://192.168.100.1", "http://other.host/login")
        assert result == "http://other.host/login"


class TestLoginPageDetection:
    """Test login page detection helper."""

    def test_detects_password_input(self):
        """Test detecting password input."""
        handler = AuthHandler(strategy=AuthStrategyType.FORM_PLAIN)
        html = '<html><form><input type="password" name="pass"></form></html>'
        assert handler._is_login_page(html) is True

    def test_no_password_input(self):
        """Test page without password input."""
        handler = AuthHandler(strategy=AuthStrategyType.FORM_PLAIN)
        html = "<html><h1>Status Page</h1></html>"
        assert handler._is_login_page(html) is False

    def test_empty_html(self):
        """Test empty HTML returns False."""
        handler = AuthHandler(strategy=AuthStrategyType.FORM_PLAIN)
        assert handler._is_login_page("") is False
        assert handler._is_login_page(None) is False

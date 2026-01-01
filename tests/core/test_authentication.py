"""Tests for Authentication Strategies."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from custom_components.cable_modem_monitor.core.auth import (
    AuthStrategyType,
    BasicHttpAuthStrategy,
    FormAuthConfig,
    FormBase64AuthStrategy,
    FormPlainAndBase64AuthStrategy,
    FormPlainAuthStrategy,
    HNAPAuthConfig,
    HNAPSessionAuthStrategy,
    NoAuthStrategy,
    RedirectFormAuthConfig,
    RedirectFormAuthStrategy,
    UrlTokenSessionConfig,
    UrlTokenSessionStrategy,
)


@pytest.fixture
def mock_session():
    """Create a mock requests session."""
    session = MagicMock(spec=requests.Session)
    session.verify = False
    return session


@pytest.fixture
def form_auth_config():
    """Create a form auth configuration."""
    return FormAuthConfig(
        strategy=AuthStrategyType.FORM_PLAIN,
        login_url="/login.asp",
        username_field="username",
        password_field="password",
        success_indicator="/status.asp",
    )


class TestNoAuthStrategy:
    """Test NoAuthStrategy."""

    def test_no_auth_always_succeeds(self, mock_session):
        """Test that NoAuthStrategy always returns success."""
        strategy = NoAuthStrategy()
        config = MagicMock()

        success, response = strategy.login(mock_session, "http://192.168.1.1", None, None, config)

        assert success is True
        assert response is None

    def test_no_auth_with_credentials(self, mock_session):
        """Test NoAuthStrategy ignores credentials."""
        strategy = NoAuthStrategy()
        config = MagicMock()

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", config)

        assert success is True
        assert response is None


class TestBasicHttpAuthStrategy:
    """Test BasicHttpAuthStrategy."""

    def test_basic_auth_sets_session_auth(self, mock_session):
        """Test that Basic Auth sets credentials on session."""
        strategy = BasicHttpAuthStrategy()
        config = MagicMock()

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", config)

        assert success is True
        assert response is None
        assert mock_session.auth == ("admin", "password")

    def test_basic_auth_without_credentials(self, mock_session):
        """Test Basic Auth without credentials."""
        strategy = BasicHttpAuthStrategy()
        config = MagicMock()

        success, response = strategy.login(mock_session, "http://192.168.1.1", None, None, config)

        assert success is True
        assert response is None
        assert not hasattr(mock_session, "auth") or mock_session.auth is None

    def test_basic_auth_missing_username(self, mock_session):
        """Test Basic Auth with missing username."""
        strategy = BasicHttpAuthStrategy()
        config = MagicMock()

        success, response = strategy.login(mock_session, "http://192.168.1.1", None, "password", config)

        assert success is True
        assert response is None

    def test_basic_auth_missing_password(self, mock_session):
        """Test Basic Auth with missing password."""
        strategy = BasicHttpAuthStrategy()
        config = MagicMock()

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", None, config)

        assert success is True
        assert response is None


class TestFormPlainAuthStrategy:
    """Test FormPlainAuthStrategy."""

    def test_form_auth_success(self, mock_session, form_auth_config):
        """Test successful form authentication."""
        strategy = FormPlainAuthStrategy()

        # Mock successful response
        mock_response = MagicMock()
        mock_response.url = "http://192.168.1.1/status.asp"  # Success indicator
        mock_response.text = "<html>Logged in</html>"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", form_auth_config)

        assert success is True
        assert response is not None

        # Verify POST call
        mock_session.post.assert_called_once()
        call_args = mock_session.post.call_args
        assert call_args[0][0] == "http://192.168.1.1/login.asp"
        assert call_args[1]["data"] == {"username": "admin", "password": "password"}

    def test_form_auth_without_credentials(self, mock_session, form_auth_config):
        """Test form auth without credentials."""
        strategy = FormPlainAuthStrategy()

        success, response = strategy.login(mock_session, "http://192.168.1.1", None, None, form_auth_config)

        assert success is True
        assert response is None
        mock_session.post.assert_not_called()

    def test_form_auth_wrong_config_type(self, mock_session):
        """Test form auth with wrong config type."""
        strategy = FormPlainAuthStrategy()
        wrong_config = MagicMock()  # Not a FormAuthConfig

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", wrong_config)

        assert success is False
        assert response is None

    def test_form_auth_large_response_indicator(self, mock_session):
        """Test form auth with size-based success indicator."""
        # Config with digit success indicator (response size check)
        config = FormAuthConfig(
            strategy=AuthStrategyType.FORM_PLAIN,
            login_url="/login.asp",
            username_field="username",
            password_field="password",
            success_indicator="1000",  # Response must be > 1000 bytes
        )

        strategy = FormPlainAuthStrategy()

        # Mock large response
        mock_response = MagicMock()
        mock_response.url = "http://192.168.1.1/other.asp"
        mock_response.text = "x" * 2000  # 2000 bytes
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", config)

        assert success is True


class TestFormBase64AuthStrategy:
    """Test FormBase64AuthStrategy."""

    @pytest.fixture
    def form_base64_config(self):
        """Create a form auth configuration for Base64."""
        return FormAuthConfig(
            strategy=AuthStrategyType.FORM_BASE64,
            login_url="/login.asp",
            username_field="username",
            password_field="password",
            success_indicator="/status.asp",
        )

    def test_form_base64_encodes_password(self, mock_session, form_base64_config):
        """Test that Base64 auth encodes the password."""
        import base64

        strategy = FormBase64AuthStrategy()

        mock_response = MagicMock()
        mock_response.url = "http://192.168.1.1/status.asp"
        mock_response.text = "<html>Logged in</html>"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", form_base64_config)

        assert success is True
        assert response is not None

        # Verify password was Base64 encoded
        call_args = mock_session.post.call_args
        sent_password = call_args[1]["data"]["password"]
        expected_encoded = base64.b64encode(b"password").decode("utf-8")
        assert sent_password == expected_encoded

    def test_form_base64_without_credentials(self, mock_session, form_base64_config):
        """Test Base64 auth without credentials skips login."""
        strategy = FormBase64AuthStrategy()

        success, response = strategy.login(mock_session, "http://192.168.1.1", None, None, form_base64_config)

        assert success is True
        assert response is None
        mock_session.post.assert_not_called()

    def test_form_base64_wrong_config_type(self, mock_session):
        """Test Base64 auth with wrong config type."""
        strategy = FormBase64AuthStrategy()
        wrong_config = MagicMock()

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", wrong_config)

        assert success is False
        assert response is None

    def test_form_base64_success_indicator_in_url(self, mock_session, form_base64_config):
        """Test success detection via URL pattern."""
        strategy = FormBase64AuthStrategy()

        mock_response = MagicMock()
        mock_response.url = "http://192.168.1.1/status.asp?logged=true"
        mock_response.text = "<html>Status</html>"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", form_base64_config)

        assert success is True

    def test_form_base64_success_indicator_by_size(self, mock_session):
        """Test success detection via response size."""
        config = FormAuthConfig(
            strategy=AuthStrategyType.FORM_BASE64,
            login_url="/login.asp",
            username_field="username",
            password_field="password",
            success_indicator="500",  # Response must be > 500 bytes
        )
        strategy = FormBase64AuthStrategy()

        mock_response = MagicMock()
        mock_response.url = "http://192.168.1.1/other.asp"
        mock_response.text = "x" * 600
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", config)

        assert success is True

    def test_form_base64_no_success_indicator(self, mock_session):
        """Test success detection via status code when no indicator."""
        config = FormAuthConfig(
            strategy=AuthStrategyType.FORM_BASE64,
            login_url="/login.asp",
            username_field="username",
            password_field="password",
            success_indicator=None,
        )
        strategy = FormBase64AuthStrategy()

        mock_response = MagicMock()
        mock_response.url = "http://192.168.1.1/other.asp"
        mock_response.text = "<html>OK</html>"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", config)

        assert success is True


class TestFormPlainAndBase64AuthStrategy:
    """Test FormPlainAndBase64AuthStrategy (fallback strategy)."""

    @pytest.fixture
    def form_fallback_config(self):
        """Create a form auth configuration for fallback."""
        return FormAuthConfig(
            strategy=AuthStrategyType.FORM_PLAIN_AND_BASE64,
            login_url="/login.asp",
            username_field="username",
            password_field="password",
            success_indicator="/status.asp",
        )

    def test_fallback_tries_plain_first(self, mock_session, form_fallback_config):
        """Test that fallback tries plain password first."""
        strategy = FormPlainAndBase64AuthStrategy()

        # First call (plain) succeeds
        mock_response = MagicMock()
        mock_response.url = "http://192.168.1.1/status.asp"
        mock_response.text = "<html>Logged in</html>"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        success, response = strategy.login(
            mock_session, "http://192.168.1.1", "admin", "password", form_fallback_config
        )

        assert success is True
        # Should only call once (plain worked)
        assert mock_session.post.call_count == 1
        # Verify plain password was sent
        call_args = mock_session.post.call_args
        assert call_args[1]["data"]["password"] == "password"

    def test_fallback_tries_base64_on_plain_failure(self, mock_session, form_fallback_config):
        """Test that fallback tries Base64 when plain fails."""
        import base64

        strategy = FormPlainAndBase64AuthStrategy()

        # First call (plain) fails, second (base64) succeeds
        mock_fail_response = MagicMock()
        mock_fail_response.url = "http://192.168.1.1/login.asp"  # Still on login page
        mock_fail_response.text = "Login failed"
        mock_fail_response.status_code = 200

        mock_success_response = MagicMock()
        mock_success_response.url = "http://192.168.1.1/status.asp"
        mock_success_response.text = "<html>Logged in</html>"
        mock_success_response.status_code = 200

        mock_session.post.side_effect = [mock_fail_response, mock_success_response]

        success, response = strategy.login(
            mock_session, "http://192.168.1.1", "admin", "password", form_fallback_config
        )

        assert success is True
        assert mock_session.post.call_count == 2

        # Verify second call used Base64
        second_call = mock_session.post.call_args_list[1]
        expected_encoded = base64.b64encode(b"password").decode("utf-8")
        assert second_call[1]["data"]["password"] == expected_encoded

    def test_fallback_fails_when_both_fail(self, mock_session, form_fallback_config):
        """Test that fallback fails when both methods fail."""
        strategy = FormPlainAndBase64AuthStrategy()

        mock_fail_response = MagicMock()
        mock_fail_response.url = "http://192.168.1.1/login.asp"
        mock_fail_response.text = "Login failed"
        mock_fail_response.status_code = 200
        mock_session.post.return_value = mock_fail_response

        success, response = strategy.login(
            mock_session, "http://192.168.1.1", "admin", "password", form_fallback_config
        )

        assert success is False
        assert mock_session.post.call_count == 2

    def test_fallback_without_credentials(self, mock_session, form_fallback_config):
        """Test fallback without credentials skips login."""
        strategy = FormPlainAndBase64AuthStrategy()

        success, response = strategy.login(mock_session, "http://192.168.1.1", None, None, form_fallback_config)

        assert success is True
        assert response is None
        mock_session.post.assert_not_called()

    def test_fallback_wrong_config_type(self, mock_session):
        """Test fallback with wrong config type."""
        strategy = FormPlainAndBase64AuthStrategy()
        wrong_config = MagicMock()

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", wrong_config)

        assert success is False
        assert response is None


class TestRedirectFormAuthStrategy:
    """Test RedirectFormAuthStrategy."""

    @pytest.fixture
    def redirect_form_config(self):
        """Create a redirect form auth configuration."""
        return RedirectFormAuthConfig(
            strategy=AuthStrategyType.REDIRECT_FORM,
            login_url="/check.jst",
            username_field="username",
            password_field="password",
            success_redirect_pattern="/home.jst",
            authenticated_page_url="/network_setup.jst",
        )

    def test_redirect_form_success(self, mock_session, redirect_form_config):
        """Test successful redirect form authentication."""
        strategy = RedirectFormAuthStrategy()

        # Mock login POST response
        mock_login_response = MagicMock()
        mock_login_response.url = "http://192.168.1.1/home.jst"
        mock_login_response.status_code = 200
        mock_login_response.text = "<html>Home</html>"

        # Mock authenticated page GET response
        mock_auth_response = MagicMock()
        mock_auth_response.status_code = 200
        mock_auth_response.text = "<html>Network Setup</html>"

        mock_session.post.return_value = mock_login_response
        mock_session.get.return_value = mock_auth_response

        success, response = strategy.login(
            mock_session, "http://192.168.1.1", "admin", "password", redirect_form_config
        )

        assert success is True
        assert response == "<html>Network Setup</html>"
        mock_session.post.assert_called_once()
        mock_session.get.assert_called_once()

    def test_redirect_form_without_credentials(self, mock_session, redirect_form_config):
        """Test redirect form requires credentials."""
        strategy = RedirectFormAuthStrategy()

        success, response = strategy.login(mock_session, "http://192.168.1.1", None, None, redirect_form_config)

        assert success is False
        assert response is None
        mock_session.post.assert_not_called()

    def test_redirect_form_wrong_config_type(self, mock_session):
        """Test redirect form with wrong config type."""
        strategy = RedirectFormAuthStrategy()
        wrong_config = MagicMock()

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", wrong_config)

        assert success is False
        assert response is None

    def test_redirect_form_login_http_error(self, mock_session, redirect_form_config):
        """Test redirect form handles HTTP error."""
        strategy = RedirectFormAuthStrategy()

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_session.post.return_value = mock_response

        success, response = strategy.login(
            mock_session, "http://192.168.1.1", "admin", "password", redirect_form_config
        )

        assert success is False

    def test_redirect_form_wrong_redirect(self, mock_session, redirect_form_config):
        """Test redirect form fails on wrong redirect."""
        strategy = RedirectFormAuthStrategy()

        mock_response = MagicMock()
        mock_response.url = "http://192.168.1.1/login.jst"  # Wrong redirect
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        success, response = strategy.login(
            mock_session, "http://192.168.1.1", "admin", "password", redirect_form_config
        )

        assert success is False

    def test_redirect_form_cross_host_security(self, mock_session, redirect_form_config):
        """Test redirect form rejects cross-host redirects."""
        strategy = RedirectFormAuthStrategy()

        mock_response = MagicMock()
        mock_response.url = "http://malicious.com/home.jst"  # Different host!
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        success, response = strategy.login(
            mock_session, "http://192.168.1.1", "admin", "password", redirect_form_config
        )

        assert success is False

    def test_redirect_form_timeout_handling(self, mock_session, redirect_form_config):
        """Test redirect form handles timeout."""
        strategy = RedirectFormAuthStrategy()

        mock_session.post.side_effect = requests.exceptions.Timeout("Connection timed out")

        success, response = strategy.login(
            mock_session, "http://192.168.1.1", "admin", "password", redirect_form_config
        )

        assert success is False

    def test_redirect_form_connection_error(self, mock_session, redirect_form_config):
        """Test redirect form handles connection error."""
        strategy = RedirectFormAuthStrategy()

        mock_session.post.side_effect = requests.exceptions.ConnectionError("Connection failed")

        success, response = strategy.login(
            mock_session, "http://192.168.1.1", "admin", "password", redirect_form_config
        )

        assert success is False

    def test_redirect_form_authenticated_page_error(self, mock_session, redirect_form_config):
        """Test redirect form handles authenticated page fetch failure."""
        strategy = RedirectFormAuthStrategy()

        mock_login_response = MagicMock()
        mock_login_response.url = "http://192.168.1.1/home.jst"
        mock_login_response.status_code = 200
        mock_session.post.return_value = mock_login_response

        mock_auth_response = MagicMock()
        mock_auth_response.status_code = 500
        mock_session.get.return_value = mock_auth_response

        success, response = strategy.login(
            mock_session, "http://192.168.1.1", "admin", "password", redirect_form_config
        )

        assert success is False


class TestHNAPSessionAuthStrategy:
    """Test HNAPSessionAuthStrategy."""

    @pytest.fixture
    def hnap_config(self):
        """Create an HNAP auth configuration."""
        return HNAPAuthConfig(
            strategy=AuthStrategyType.HNAP_SESSION,
            login_url="/Login.html",
            hnap_endpoint="/HNAP1/",
            soap_action_namespace="http://purenetworks.com/HNAP1/",
            session_timeout_indicator="UNAUTHORIZED",
        )

    def test_hnap_session_success(self, mock_session, hnap_config):
        """Test successful HNAP session authentication."""
        strategy = HNAPSessionAuthStrategy()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<LoginResult>OK</LoginResult>"
        mock_response.headers = {"Content-Type": "text/xml"}
        mock_session.post.return_value = mock_response

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", hnap_config)

        assert success is True
        assert response is not None

        # Verify SOAP action header
        call_args = mock_session.post.call_args
        assert call_args[1]["headers"]["SOAPAction"] == '"http://purenetworks.com/HNAP1/Login"'

    def test_hnap_session_without_credentials(self, mock_session, hnap_config):
        """Test HNAP session requires credentials."""
        strategy = HNAPSessionAuthStrategy()

        success, response = strategy.login(mock_session, "http://192.168.1.1", None, None, hnap_config)

        assert success is False
        mock_session.post.assert_not_called()

    def test_hnap_session_wrong_config_type(self, mock_session):
        """Test HNAP session with wrong config type."""
        strategy = HNAPSessionAuthStrategy()
        wrong_config = MagicMock()

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", wrong_config)

        assert success is False

    def test_hnap_session_http_error(self, mock_session, hnap_config):
        """Test HNAP session handles HTTP error."""
        strategy = HNAPSessionAuthStrategy()

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_session.post.return_value = mock_response

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", hnap_config)

        assert success is False

    def test_hnap_session_timeout_indicator(self, mock_session, hnap_config):
        """Test HNAP session detects timeout indicator."""
        strategy = HNAPSessionAuthStrategy()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<LoginResult>UNAUTHORIZED</LoginResult>"
        mock_response.headers = {"Content-Type": "text/xml"}
        mock_session.post.return_value = mock_response

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", hnap_config)

        assert success is False

    def test_hnap_session_json_error_response(self, mock_session, hnap_config):
        """Test HNAP session detects JSON error response."""
        strategy = HNAPSessionAuthStrategy()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"LoginResult":"FAILED"}'
        mock_response.headers = {"Content-Type": "application/json"}
        mock_session.post.return_value = mock_response

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", hnap_config)

        assert success is False

    def test_hnap_session_timeout_handling(self, mock_session, hnap_config):
        """Test HNAP session handles timeout."""
        strategy = HNAPSessionAuthStrategy()

        mock_session.post.side_effect = requests.exceptions.Timeout("Connection timed out")

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", hnap_config)

        assert success is False

    def test_hnap_session_connection_error(self, mock_session, hnap_config):
        """Test HNAP session handles connection error."""
        strategy = HNAPSessionAuthStrategy()

        mock_session.post.side_effect = requests.exceptions.ConnectionError("Connection failed")

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", hnap_config)

        assert success is False

    def test_hnap_session_builds_correct_envelope(self, mock_session, hnap_config):
        """Test HNAP session builds correct SOAP envelope."""
        strategy = HNAPSessionAuthStrategy()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<LoginResult>OK</LoginResult>"
        mock_response.headers = {"Content-Type": "text/xml"}
        mock_session.post.return_value = mock_response

        success, response = strategy.login(mock_session, "http://192.168.1.1", "admin", "password", hnap_config)

        # Verify envelope contains username and password
        call_args = mock_session.post.call_args
        envelope = call_args[1]["data"]
        assert "<Username>admin</Username>" in envelope
        assert "<Password>password</Password>" in envelope
        assert 'xmlns="http://purenetworks.com/HNAP1/"' in envelope


class TestAuthStrategyFactoryPattern:
    """Test that auth strategies can be instantiated and used polymorphically."""

    @pytest.mark.parametrize(
        "strategy_class",
        [
            NoAuthStrategy,
            BasicHttpAuthStrategy,
            FormPlainAuthStrategy,
            FormBase64AuthStrategy,
            FormPlainAndBase64AuthStrategy,
            RedirectFormAuthStrategy,
            HNAPSessionAuthStrategy,
            UrlTokenSessionStrategy,
        ],
    )
    def test_all_strategies_have_login_method(self, strategy_class):
        """Test that all strategies implement login method."""
        strategy = strategy_class()

        assert hasattr(strategy, "login")
        assert callable(strategy.login)


class TestUrlTokenSessionStrategy:
    """Test UrlTokenSessionStrategy (e.g., ARRIS SB8200 HTTPS variant)."""

    @pytest.fixture
    def url_token_config(self):
        """Create URL token session config."""
        return UrlTokenSessionConfig(
            strategy=AuthStrategyType.URL_TOKEN_SESSION,
            login_page="/cmconnectionstatus.html",
            data_page="/cmconnectionstatus.html",
            login_prefix="login_",
            token_prefix="ct_",
            session_cookie_name="sessionId",
            success_indicator="Downstream Bonded Channels",
        )

    def test_no_credentials_skips_auth(self, mock_session, url_token_config):
        """Test that missing credentials skips auth."""
        strategy = UrlTokenSessionStrategy()

        success, response = strategy.login(mock_session, "https://192.168.100.1", None, None, url_token_config)

        assert success is True
        assert response is None
        mock_session.get.assert_not_called()

    def test_empty_credentials_skips_auth(self, mock_session, url_token_config):
        """Test that empty credentials skips auth."""
        strategy = UrlTokenSessionStrategy()

        success, response = strategy.login(mock_session, "https://192.168.100.1", "", "", url_token_config)

        assert success is True
        assert response is None
        mock_session.get.assert_not_called()

    def test_login_url_contains_base64_token(self, mock_session, url_token_config):
        """Test that login URL contains base64-encoded credentials."""
        import base64

        strategy = UrlTokenSessionStrategy()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Downstream Bonded Channels data here"
        mock_session.get.return_value = mock_response

        strategy.login(mock_session, "https://192.168.100.1", "admin", "password", url_token_config)

        # Check that the login URL contains the base64 token
        expected_token = base64.b64encode(b"admin:password").decode("utf-8")
        call_url = mock_session.get.call_args[0][0]
        assert f"login_{expected_token}" in call_url

    def test_login_includes_authorization_header(self, mock_session, url_token_config):
        """Test that login request includes Authorization header."""
        import base64

        strategy = UrlTokenSessionStrategy()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Downstream Bonded Channels data here"
        mock_session.get.return_value = mock_response

        strategy.login(mock_session, "https://192.168.100.1", "admin", "password", url_token_config)

        # Check that Authorization header was included
        expected_token = base64.b64encode(b"admin:password").decode("utf-8")
        call_kwargs = mock_session.get.call_args[1]
        assert "headers" in call_kwargs
        assert call_kwargs["headers"]["Authorization"] == f"Basic {expected_token}"

    def test_success_when_data_in_login_response(self, mock_session, url_token_config):
        """Test success when login response contains channel data."""
        strategy = UrlTokenSessionStrategy()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>Downstream Bonded Channels table here</html>"
        mock_session.get.return_value = mock_response

        success, response = strategy.login(mock_session, "https://192.168.100.1", "admin", "password", url_token_config)

        assert success is True
        assert response == mock_response.text

    def test_fetches_data_page_with_session_token(self, url_token_config):
        """Test that data page is fetched with session token from cookie."""
        strategy = UrlTokenSessionStrategy()

        # Create session with cookies mock
        session = MagicMock(spec=requests.Session)
        session.cookies = MagicMock()
        session.cookies.get.return_value = "test_session_id_123"

        # First response (login) - no channel data, sets cookie
        login_response = MagicMock()
        login_response.status_code = 200
        login_response.text = ""  # Empty body

        # Second response (data page) - has channel data
        data_response = MagicMock()
        data_response.status_code = 200
        data_response.text = "<html>Downstream Bonded Channels</html>"

        session.get.side_effect = [login_response, data_response]

        success, response = strategy.login(session, "https://192.168.100.1", "admin", "password", url_token_config)

        assert success is True
        assert response == data_response.text

        # Verify second call used session token
        second_call_url = session.get.call_args_list[1][0][0]
        assert "ct_test_session_id_123" in second_call_url

    def test_401_returns_failure(self, mock_session, url_token_config):
        """Test that 401 response returns failure."""
        strategy = UrlTokenSessionStrategy()
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_session.get.return_value = mock_response

        success, response = strategy.login(
            mock_session, "https://192.168.100.1", "admin", "wrong_password", url_token_config
        )

        assert success is False
        assert "401" in str(response)

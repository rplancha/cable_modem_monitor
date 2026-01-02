"""Tests for Authentication Discovery."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from custom_components.cable_modem_monitor.core.auth import AuthStrategyType
from custom_components.cable_modem_monitor.core.auth.discovery import (
    AuthDiscovery,
    DiscoveredFormConfig,
)


@pytest.fixture
def mock_session():
    """Create a mock requests session."""
    session = MagicMock(spec=requests.Session)
    session.verify = False
    return session


@pytest.fixture
def mock_parser():
    """Create a mock parser that can parse data."""
    parser = MagicMock()
    parser.name = "Test Parser"
    parser.auth_form_hints = {}
    parser.js_auth_hints = None
    parser.parse.return_value = {
        "downstream": [{"channel": 1}],
        "upstream": [{"channel": 1}],
    }
    return parser


@pytest.fixture
def discovery():
    """Create an AuthDiscovery instance."""
    return AuthDiscovery()


class TestDiscoveredFormConfig:
    """Test DiscoveredFormConfig dataclass."""

    def test_to_dict(self):
        """Test serialization to dict."""
        config = DiscoveredFormConfig(
            action="/login",
            method="POST",
            username_field="user",
            password_field="pass",
            hidden_fields={"csrf": "token123"},
        )

        result = config.to_dict()

        assert result == {
            "action": "/login",
            "method": "POST",
            "username_field": "user",
            "password_field": "pass",
            "hidden_fields": {"csrf": "token123"},
        }

    def test_from_dict(self):
        """Test deserialization from dict."""
        data = {
            "action": "/auth",
            "method": "GET",
            "username_field": "username",
            "password_field": "password",
            "hidden_fields": {},
        }

        config = DiscoveredFormConfig.from_dict(data)

        assert config.action == "/auth"
        assert config.method == "GET"
        assert config.username_field == "username"
        assert config.password_field == "password"
        assert config.hidden_fields == {}

    def test_roundtrip(self):
        """Test serialization and deserialization roundtrip."""
        original = DiscoveredFormConfig(
            action="/submit",
            method="POST",
            username_field="loginUser",
            password_field="loginPass",
            hidden_fields={"nonce": "abc", "session": "xyz"},
        )

        serialized = original.to_dict()
        restored = DiscoveredFormConfig.from_dict(serialized)

        assert restored.action == original.action
        assert restored.method == original.method
        assert restored.username_field == original.username_field
        assert restored.password_field == original.password_field
        assert restored.hidden_fields == original.hidden_fields


class TestAuthDiscoveryNoAuth:
    """Test detection of no-auth modems."""

    def test_200_with_parseable_data_returns_no_auth(self, discovery, mock_session, mock_parser):
        """Test that 200 with parseable data returns NO_AUTH."""
        # Mock response with parseable data
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><table>Channel data</table></html>"
        mock_response.url = "http://192.168.100.1/status.html"
        mock_session.get.return_value = mock_response

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/status.html",
            username=None,
            password=None,
            parser=mock_parser,
        )

        assert result.success is True
        assert result.strategy == AuthStrategyType.NO_AUTH
        assert result.response_html == mock_response.text
        assert result.error_message is None

    def test_200_with_parseable_data_ignores_credentials(self, discovery, mock_session, mock_parser):
        """Test that 200 with parseable data ignores provided credentials."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><table>Channel data</table></html>"
        mock_response.url = "http://192.168.100.1/status.html"
        mock_session.get.return_value = mock_response

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/status.html",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        assert result.success is True
        assert result.strategy == AuthStrategyType.NO_AUTH


class TestAuthDiscoveryBasicAuth:
    """Test detection of HTTP Basic auth."""

    def test_401_triggers_basic_auth(self, discovery, mock_session, mock_parser):
        """Test that 401 response triggers Basic Auth."""
        # First request returns 401
        mock_401 = MagicMock()
        mock_401.status_code = 401
        mock_401.text = "Unauthorized"
        mock_401.url = "http://192.168.100.1/status.html"

        # Second request (with auth) returns 200
        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.text = "<html><table>Channel data</table></html>"

        mock_session.get.side_effect = [mock_401, mock_200]

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/status.html",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        assert result.success is True
        assert result.strategy == AuthStrategyType.BASIC_HTTP
        assert mock_session.auth == ("admin", "password")

    def test_401_without_credentials_returns_error(self, discovery, mock_session, mock_parser):
        """Test that 401 without credentials returns error."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_response.url = "http://192.168.100.1/status.html"
        mock_session.get.return_value = mock_response

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/status.html",
            username=None,
            password=None,
            parser=mock_parser,
        )

        assert result.success is False
        assert "Authentication required" in result.error_message

    def test_401_with_invalid_credentials_returns_error(self, discovery, mock_session, mock_parser):
        """Test that 401 after auth retry returns invalid credentials error."""
        # Both requests return 401
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_response.url = "http://192.168.100.1/status.html"
        mock_session.get.return_value = mock_response

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/status.html",
            username="admin",
            password="wrongpassword",
            parser=mock_parser,
        )

        assert result.success is False
        assert "Invalid credentials" in result.error_message


class TestAuthDiscoveryFormAuth:
    """Test detection of form-based auth."""

    def test_login_form_detected(self, discovery, mock_session, mock_parser):
        """Test that login form is detected."""
        # First request returns login form
        mock_form = MagicMock()
        mock_form.status_code = 200
        mock_form.text = """
        <html>
        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="submit" value="Login" />
        </form>
        </html>
        """
        mock_form.url = "http://192.168.100.1/login.html"

        # Form submission succeeds
        mock_post = MagicMock()
        mock_post.status_code = 200
        mock_post.text = "Logged in"  # Not a login form

        # Data page after login has data
        mock_data = MagicMock()
        mock_data.status_code = 200
        mock_data.text = "<html><table>Channel data</table></html>"

        mock_session.get.side_effect = [mock_form, mock_data]
        mock_session.post.return_value = mock_post

        # Parser can't parse login form, but can parse data after auth
        def parse_side_effect(soup, session=None, base_url=None):
            text = str(soup)
            if "Channel data" in text:
                return {"downstream": [{"channel": 1}], "upstream": []}
            return {"downstream": [], "upstream": []}

        mock_parser.parse.side_effect = parse_side_effect

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/status.html",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        assert result.success is True
        assert result.strategy == AuthStrategyType.FORM_PLAIN
        assert result.form_config is not None
        assert result.form_config.action == "/login"
        assert result.form_config.username_field == "username"
        assert result.form_config.password_field == "password"

    def test_login_form_without_credentials_returns_error(self, discovery, mock_session, mock_parser):
        """Test that login form without credentials returns error."""
        mock_parser.parse.return_value = {"downstream": [], "upstream": []}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
        <form action="/login" method="POST">
            <input type="text" name="user" />
            <input type="password" name="pass" />
        </form>
        """
        mock_response.url = "http://192.168.100.1/login.html"
        mock_session.get.return_value = mock_response

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/status.html",
            username=None,
            password=None,
            parser=mock_parser,
        )

        assert result.success is False
        assert "Login form detected" in result.error_message

    def test_form_hidden_fields_captured(self, discovery):
        """Test that hidden fields are captured from form."""
        html = """
        <form action="/auth" method="POST">
            <input type="hidden" name="csrf_token" value="abc123" />
            <input type="hidden" name="session_id" value="xyz789" />
            <input type="text" name="username" />
            <input type="password" name="password" />
        </form>
        """

        mock_parser = MagicMock()
        mock_parser.auth_form_hints = {}

        config = discovery._parse_login_form(html, mock_parser)

        assert config is not None
        assert config.hidden_fields == {"csrf_token": "abc123", "session_id": "xyz789"}


class TestFormIntrospection:
    """Test form field detection."""

    @pytest.fixture
    def discovery(self):
        return AuthDiscovery()

    @pytest.fixture
    def mock_parser(self):
        parser = MagicMock()
        parser.auth_form_hints = {}
        return parser

    def test_find_username_by_name_hint(self, discovery, mock_parser):
        """Test finding username field by name hint."""
        html = """
        <form>
            <input type="text" name="loginUsername" />
            <input type="password" name="pass" />
        </form>
        """

        config = discovery._parse_login_form(html, mock_parser)

        assert config.username_field == "loginUsername"

    def test_find_username_by_user_hint(self, discovery, mock_parser):
        """Test finding username field by 'user' hint."""
        html = """
        <form>
            <input type="text" name="webUser" />
            <input type="password" name="webPass" />
        </form>
        """

        config = discovery._parse_login_form(html, mock_parser)

        assert config.username_field == "webUser"

    def test_find_username_fallback_first_text(self, discovery, mock_parser):
        """Test fallback to first text input when no hints match."""
        html = """
        <form>
            <input type="text" name="field1" />
            <input type="password" name="secret" />
        </form>
        """

        config = discovery._parse_login_form(html, mock_parser)

        assert config.username_field == "field1"

    def test_find_password_by_type(self, discovery, mock_parser):
        """Test finding password field by type='password'."""
        html = """
        <form>
            <input type="text" name="username" />
            <input type="password" name="mySecretField" />
        </form>
        """

        config = discovery._parse_login_form(html, mock_parser)

        assert config.password_field == "mySecretField"

    def test_form_action_extracted(self, discovery, mock_parser):
        """Test form action URL extraction."""
        html = """
        <form action="/cgi-bin/login.cgi" method="POST">
            <input type="text" name="user" />
            <input type="password" name="pass" />
        </form>
        """

        config = discovery._parse_login_form(html, mock_parser)

        assert config.action == "/cgi-bin/login.cgi"

    def test_form_method_defaults_post(self, discovery, mock_parser):
        """Test form method defaults to POST."""
        html = """
        <form>
            <input type="text" name="user" />
            <input type="password" name="pass" />
        </form>
        """

        config = discovery._parse_login_form(html, mock_parser)

        assert config.method == "POST"

    def test_no_form_returns_none(self, discovery, mock_parser):
        """Test that no form element returns None."""
        html = "<html><body>No form here</body></html>"

        config = discovery._parse_login_form(html, mock_parser)

        assert config is None

    def test_no_password_field_returns_none(self, discovery, mock_parser):
        """Test that form without password field returns None."""
        html = """
        <form>
            <input type="text" name="search" />
            <input type="submit" value="Search" />
        </form>
        """

        config = discovery._parse_login_form(html, mock_parser)

        assert config is None

    def test_parser_hints_override_detection(self, discovery):
        """Test that parser hints override generic detection."""
        html = """
        <form>
            <input type="text" name="field1" />
            <input type="password" name="field2" />
        </form>
        """

        mock_parser = MagicMock()
        mock_parser.auth_form_hints = {
            "username_field": "customUser",
            "password_field": "customPass",
        }

        # Parser hints should be used even though they don't exist in the form
        # (this tests the precedence, not validation)
        config = discovery._parse_login_form(html, mock_parser)

        assert config.username_field == "customUser"
        # Password field should still be found since customPass doesn't exist
        # and we only use hints if they're provided AND the field isn't found


class TestAuthDiscoveryRedirect:
    """Test redirect handling."""

    def test_meta_refresh_redirect_followed(self, discovery, mock_session, mock_parser):
        """Test that meta refresh redirect is followed."""
        # First response: meta refresh redirect
        mock_redirect = MagicMock()
        mock_redirect.status_code = 200
        mock_redirect.text = '<html><head><meta http-equiv="refresh" content="0;url=login.html"></head></html>'
        mock_redirect.url = "http://192.168.100.1/"

        # Second response: login form
        mock_form = MagicMock()
        mock_form.status_code = 200
        mock_form.text = """
        <form action="/login" method="POST">
            <input type="text" name="user" />
            <input type="password" name="pass" />
        </form>
        """
        mock_form.url = "http://192.168.100.1/login.html"

        mock_session.get.side_effect = [mock_redirect, mock_form]
        mock_parser.parse.return_value = {"downstream": [], "upstream": []}

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/",
            username=None,
            password=None,
            parser=mock_parser,
        )

        # Should have followed redirect and found login form
        assert result.success is False
        assert "Login form detected" in result.error_message
        assert mock_session.get.call_count == 2

    def test_302_redirect_followed(self, discovery, mock_session, mock_parser):
        """Test that HTTP 302 redirect is followed."""
        # First response: 302 redirect
        mock_redirect = MagicMock()
        mock_redirect.status_code = 302
        mock_redirect.headers = {"Location": "/login.html"}
        mock_redirect.text = ""
        mock_redirect.url = "http://192.168.100.1/status.html"

        # Second response: login form (with action and submit to avoid JS detection)
        mock_form = MagicMock()
        mock_form.status_code = 200
        mock_form.text = """
        <form action="/auth" method="POST">
            <input type="text" name="user" />
            <input type="password" name="pass" />
            <input type="submit" value="Login" />
        </form>
        """
        mock_form.url = "http://192.168.100.1/login.html"

        mock_session.get.side_effect = [mock_redirect, mock_form]
        mock_parser.parse.return_value = {"downstream": [], "upstream": []}

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/status.html",
            username=None,
            password=None,
            parser=mock_parser,
        )

        assert result.success is False
        assert "Login form detected" in result.error_message

    def test_redirect_loop_protection(self, discovery, mock_session, mock_parser):
        """Test that redirect loops are detected and stopped."""
        # Create infinite redirect loop
        mock_redirect = MagicMock()
        mock_redirect.status_code = 302
        mock_redirect.headers = {"Location": "/redirect"}
        mock_redirect.text = ""
        mock_redirect.url = "http://192.168.100.1/redirect"

        mock_session.get.return_value = mock_redirect

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/",
            username=None,
            password=None,
            parser=mock_parser,
        )

        assert result.success is False
        assert "Too many redirects" in result.error_message


class TestAuthDiscoveryHNAP:
    """Test HNAP detection."""

    def test_hnap_detected_by_soapaction_script(self, discovery, mock_session, mock_parser):
        """Test HNAP detection via SOAPAction.js script."""
        mock_parser.parse.return_value = {"downstream": [], "upstream": []}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
        <html>
        <head>
            <script type="text/javascript" src="js/SOAP/SOAPAction.js"></script>
        </head>
        <body>Login</body>
        </html>
        """
        mock_response.url = "http://192.168.100.1/Login.html"
        mock_session.get.return_value = mock_response

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/Login.html",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        assert result.success is True
        assert result.strategy == AuthStrategyType.HNAP_SESSION

    def test_hnap_detected_by_hnap_script(self, discovery, mock_session, mock_parser):
        """Test HNAP detection via HNAP in script path."""
        mock_parser.parse.return_value = {"downstream": [], "upstream": []}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
        <html>
        <head>
            <script src="/js/HNAP/hnap.js"></script>
        </head>
        </html>
        """
        mock_response.url = "http://192.168.100.1/Login.html"
        mock_session.get.return_value = mock_response

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/Login.html",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        assert result.success is True
        assert result.strategy == AuthStrategyType.HNAP_SESSION


class TestAuthDiscoveryJSAuth:
    """Test JavaScript-based auth detection."""

    def test_js_form_with_parser_hint(self, discovery, mock_session, mock_parser):
        """Test JS form detection with parser hint."""
        mock_parser.parse.return_value = {"downstream": [], "upstream": []}
        mock_parser.js_auth_hints = {
            "pattern": "url_token_session",
            "login_prefix": "login_",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
        <form action="">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="button" value="Login" onclick="validate()" />
        </form>
        """
        mock_response.url = "http://192.168.100.1/login.html"
        mock_session.get.return_value = mock_response

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/login.html",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        assert result.success is True
        assert result.strategy == AuthStrategyType.URL_TOKEN_SESSION

    def test_js_form_without_hint_returns_error(self, discovery, mock_session, mock_parser):
        """Test JS form without parser hint returns error."""
        mock_parser.parse.return_value = {"downstream": [], "upstream": []}
        mock_parser.js_auth_hints = None

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
        <form action="">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="button" value="Login" />
        </form>
        """
        mock_response.url = "http://192.168.100.1/login.html"
        mock_session.get.return_value = mock_response

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/login.html",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        assert result.success is False
        assert "JavaScript-based login" in result.error_message


class TestAuthDiscoveryUnknown:
    """Test unknown pattern handling."""

    def test_unknown_pattern_captured(self, discovery, mock_session, mock_parser):
        """Test that unknown patterns are captured for debugging."""
        mock_parser.parse.return_value = {"downstream": [], "upstream": []}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Some weird page</body></html>"
        mock_response.url = "http://192.168.100.1/weird.html"
        mock_response.headers = {"Content-Type": "text/html"}
        mock_session.get.return_value = mock_response

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/weird.html",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        assert result.success is False
        assert result.strategy == AuthStrategyType.UNKNOWN
        assert result.captured_response is not None
        assert result.captured_response["status_code"] == 200
        assert "html_sample" in result.captured_response
        assert "Unknown authentication protocol" in result.error_message


class TestAuthDiscoveryConnectionErrors:
    """Test connection error handling."""

    def test_connection_error_returns_failure(self, discovery, mock_session, mock_parser):
        """Test that connection errors return failure."""
        mock_session.get.side_effect = Exception("Connection refused")

        result = discovery.discover(
            session=mock_session,
            base_url="http://192.168.100.1",
            data_url="http://192.168.100.1/status.html",
            username=None,
            password=None,
            parser=mock_parser,
        )

        assert result.success is False
        assert "Connection failed" in result.error_message


class TestAuthDiscoveryURLResolution:
    """Test URL resolution."""

    def test_resolve_relative_url(self, discovery):
        """Test relative URL resolution."""
        base = "http://192.168.100.1"

        assert discovery._resolve_url(base, "/login") == "http://192.168.100.1/login"
        assert discovery._resolve_url(base, "login.html") == "http://192.168.100.1/login.html"

    def test_resolve_absolute_url(self, discovery):
        """Test absolute URL passthrough."""
        base = "http://192.168.100.1"
        absolute = "https://example.com/auth"

        assert discovery._resolve_url(base, absolute) == absolute


class TestIsLoginForm:
    """Test login form detection."""

    @pytest.fixture
    def discovery(self):
        return AuthDiscovery()

    def test_form_with_password_is_login(self, discovery):
        """Test form with password field is detected as login."""
        html = """
        <form>
            <input type="text" name="user" />
            <input type="password" name="pass" />
        </form>
        """
        assert discovery._is_login_form(html) is True

    def test_form_without_password_is_not_login(self, discovery):
        """Test form without password field is not detected as login."""
        html = """
        <form>
            <input type="text" name="search" />
            <input type="submit" value="Search" />
        </form>
        """
        assert discovery._is_login_form(html) is False

    def test_no_form_is_not_login(self, discovery):
        """Test page without form is not detected as login."""
        html = "<html><body>No form here</body></html>"
        assert discovery._is_login_form(html) is False

    def test_empty_html_is_not_login(self, discovery):
        """Test empty HTML is not detected as login."""
        assert discovery._is_login_form("") is False
        assert discovery._is_login_form(None) is False


class TestIsJsForm:
    """Test JavaScript form detection."""

    @pytest.fixture
    def discovery(self):
        return AuthDiscovery()

    def test_button_type_indicates_js(self, discovery):
        """Test that type='button' indicates JS form."""
        html = """
        <form>
            <input type="text" name="user" />
            <input type="password" name="pass" />
            <input type="button" value="Login" />
        </form>
        """
        assert discovery._is_js_form(html) is True

    def test_submit_type_is_not_js(self, discovery):
        """Test that type='submit' is not JS form."""
        html = """
        <form action="/login">
            <input type="text" name="user" />
            <input type="password" name="pass" />
            <input type="submit" value="Login" />
        </form>
        """
        assert discovery._is_js_form(html) is False

    def test_empty_action_indicates_js(self, discovery):
        """Test that empty action indicates JS form."""
        html = """
        <form action="">
            <input type="text" name="user" />
            <input type="password" name="pass" />
            <input type="submit" value="Login" />
        </form>
        """
        assert discovery._is_js_form(html) is True


class TestIsRedirect:
    """Test redirect detection."""

    @pytest.fixture
    def discovery(self):
        return AuthDiscovery()

    def test_302_is_redirect(self, discovery):
        """Test 302 status is detected as redirect."""
        response = MagicMock()
        response.status_code = 302
        response.text = ""
        assert discovery._is_redirect(response) is True

    def test_301_is_redirect(self, discovery):
        """Test 301 status is detected as redirect."""
        response = MagicMock()
        response.status_code = 301
        response.text = ""
        assert discovery._is_redirect(response) is True

    def test_meta_refresh_is_redirect(self, discovery):
        """Test meta refresh is detected as redirect."""
        response = MagicMock()
        response.status_code = 200
        response.text = '<meta http-equiv="refresh" content="0;url=login.html">'
        assert discovery._is_redirect(response) is True

    def test_200_without_meta_is_not_redirect(self, discovery):
        """Test 200 without meta refresh is not redirect."""
        response = MagicMock()
        response.status_code = 200
        response.text = "<html><body>Content</body></html>"
        assert discovery._is_redirect(response) is False

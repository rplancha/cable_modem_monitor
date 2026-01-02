"""Integration tests for Auth Discovery with real mock servers.

These tests verify that AuthDiscovery works correctly with actual HTTP servers,
as opposed to the unit tests that use mocked requests.Session.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from custom_components.cable_modem_monitor.core.auth import AuthStrategyType
from custom_components.cable_modem_monitor.core.auth.discovery import AuthDiscovery


@pytest.fixture
def mock_parser():
    """Create a mock parser that can parse the mock modem response."""
    parser = MagicMock()
    parser.name = "Test Parser"
    parser.auth_form_hints = {}
    parser.js_auth_hints = None

    # This parser can parse the MOCK_MODEM_RESPONSE from conftest.py
    def parse_data(soup, session=None, base_url=None):
        # Check if it has the downstream table
        if soup.find("table", {"id": "downstream"}) or soup.find(string=lambda s: "Channel 1" in (s or "")):
            return {"downstream": [{"channel": 1}], "upstream": []}
        return {"downstream": [], "upstream": []}

    parser.parse.side_effect = parse_data
    return parser


@pytest.fixture
def discovery():
    """Create an AuthDiscovery instance."""
    return AuthDiscovery()


class TestBasicAuthIntegration:
    """Test Basic HTTP Auth discovery with real server."""

    def test_basic_auth_without_credentials_returns_401_error(self, discovery, basic_auth_server, mock_parser):
        """Test that 401 without credentials returns appropriate error."""
        session = requests.Session()
        session.verify = False

        result = discovery.discover(
            session=session,
            base_url=basic_auth_server.url,
            data_url=f"{basic_auth_server.url}/status.html",
            username=None,
            password=None,
            parser=mock_parser,
        )

        assert result.success is False
        assert "Authentication required" in result.error_message

    def test_basic_auth_with_valid_credentials(self, discovery, basic_auth_server, mock_parser):
        """Test that valid credentials work with Basic Auth."""
        session = requests.Session()
        session.verify = False

        result = discovery.discover(
            session=session,
            base_url=basic_auth_server.url,
            data_url=f"{basic_auth_server.url}/status.html",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        assert result.success is True
        assert result.strategy == AuthStrategyType.BASIC_HTTP
        assert result.response_html is not None
        assert "Channel 1" in result.response_html

    def test_basic_auth_with_invalid_credentials(self, discovery, basic_auth_server, mock_parser):
        """Test that invalid credentials return error."""
        session = requests.Session()
        session.verify = False

        result = discovery.discover(
            session=session,
            base_url=basic_auth_server.url,
            data_url=f"{basic_auth_server.url}/status.html",
            username="admin",
            password="wrongpassword",
            parser=mock_parser,
        )

        assert result.success is False
        assert "Invalid credentials" in result.error_message


class TestFormAuthIntegration:
    """Test form-based auth discovery with real server."""

    def test_form_auth_detected(self, discovery, form_auth_server, mock_parser):
        """Test that login form is detected."""
        session = requests.Session()
        session.verify = False

        result = discovery.discover(
            session=session,
            base_url=form_auth_server.url,
            data_url=f"{form_auth_server.url}/status.html",
            username=None,
            password=None,
            parser=mock_parser,
        )

        # Without credentials, should detect the form and request creds
        assert result.success is False
        assert "Login form detected" in result.error_message

    def test_form_auth_with_valid_credentials(self, discovery, form_auth_server, mock_parser):
        """Test that valid credentials work with form auth."""
        session = requests.Session()
        session.verify = False

        result = discovery.discover(
            session=session,
            base_url=form_auth_server.url,
            data_url=f"{form_auth_server.url}/status.html",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        assert result.success is True
        assert result.strategy == AuthStrategyType.FORM_PLAIN
        assert result.form_config is not None
        assert result.form_config.username_field == "username"
        assert result.form_config.password_field == "password"
        assert "csrf_token" in result.form_config.hidden_fields
        assert result.response_html is not None
        assert "Channel 1" in result.response_html


class TestHNAPAuthIntegration:
    """Test HNAP detection with real server."""

    def test_hnap_detected_by_script(self, discovery, hnap_auth_server, mock_parser):
        """Test that HNAP is detected via SOAPAction.js script."""
        session = requests.Session()
        session.verify = False

        result = discovery.discover(
            session=session,
            base_url=hnap_auth_server.url,
            data_url=f"{hnap_auth_server.url}/Login.html",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        # HNAP should be detected and returned (actual auth handled by strategy)
        assert result.success is True
        assert result.strategy == AuthStrategyType.HNAP_SESSION


class TestRedirectAuthIntegration:
    """Test redirect handling with real server."""

    def test_meta_refresh_redirect_followed(self, discovery, redirect_auth_server, mock_parser):
        """Test that meta refresh redirect is followed to login form."""
        session = requests.Session()
        session.verify = False

        result = discovery.discover(
            session=session,
            base_url=redirect_auth_server.url,
            data_url=f"{redirect_auth_server.url}/status",
            username=None,
            password=None,
            parser=mock_parser,
        )

        # Should follow redirect and find login form
        assert result.success is False
        assert "Login form detected" in result.error_message

    def test_redirect_then_form_auth(self, discovery, redirect_auth_server, mock_parser):
        """Test that redirect followed by form auth works."""
        session = requests.Session()
        session.verify = False

        result = discovery.discover(
            session=session,
            base_url=redirect_auth_server.url,
            data_url=f"{redirect_auth_server.url}/status",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        # Should follow redirect, authenticate via form, and succeed
        assert result.success is True
        assert result.strategy == AuthStrategyType.FORM_PLAIN
        assert result.form_config is not None


class TestNoAuthIntegration:
    """Test no-auth detection with real server."""

    def test_no_auth_direct_access(self, discovery, http_server, mock_parser):
        """Test that no-auth modem is detected correctly."""
        session = requests.Session()
        session.verify = False

        result = discovery.discover(
            session=session,
            base_url=http_server.url,
            data_url=f"{http_server.url}/status.html",
            username=None,
            password=None,
            parser=mock_parser,
        )

        assert result.success is True
        assert result.strategy == AuthStrategyType.NO_AUTH
        assert result.response_html is not None
        assert "Channel 1" in result.response_html


class TestFormConfigSerialization:
    """Test that form configs survive serialization (for config entry storage)."""

    def test_form_config_roundtrip(self, discovery, form_auth_server, mock_parser):
        """Test form config serialization and deserialization."""
        session = requests.Session()
        session.verify = False

        result = discovery.discover(
            session=session,
            base_url=form_auth_server.url,
            data_url=f"{form_auth_server.url}/status.html",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        assert result.success is True
        assert result.form_config is not None

        # Serialize
        serialized = result.form_config.to_dict()
        assert isinstance(serialized, dict)
        assert "action" in serialized
        assert "username_field" in serialized
        assert "password_field" in serialized

        # Deserialize
        from custom_components.cable_modem_monitor.core.auth.discovery import (
            DiscoveredFormConfig,
        )

        restored = DiscoveredFormConfig.from_dict(serialized)
        assert restored.action == result.form_config.action
        assert restored.username_field == result.form_config.username_field
        assert restored.password_field == result.form_config.password_field
        assert restored.hidden_fields == result.form_config.hidden_fields


class TestSessionPersistence:
    """Test that authenticated sessions work correctly."""

    def test_session_cookies_persist_after_form_auth(self, discovery, form_auth_server, mock_parser):
        """Test that session cookies are maintained after auth."""
        session = requests.Session()
        session.verify = False

        # Discover auth
        result = discovery.discover(
            session=session,
            base_url=form_auth_server.url,
            data_url=f"{form_auth_server.url}/status.html",
            username="admin",
            password="password",
            parser=mock_parser,
        )

        assert result.success is True

        # Session should now have cookies that allow access
        # Make a follow-up request
        response = session.get(f"{form_auth_server.url}/status.html")
        assert response.status_code == 200
        assert "Channel 1" in response.text


class TestConnectionErrors:
    """Test handling of connection errors."""

    def test_connection_refused(self, discovery, mock_parser):
        """Test that connection errors are handled gracefully."""
        session = requests.Session()
        session.verify = False

        result = discovery.discover(
            session=session,
            base_url="http://127.0.0.1:1",  # Invalid port
            data_url="http://127.0.0.1:1/status.html",
            username=None,
            password=None,
            parser=mock_parser,
        )

        assert result.success is False
        assert "Connection failed" in result.error_message

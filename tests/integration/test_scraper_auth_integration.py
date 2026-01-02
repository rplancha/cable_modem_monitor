"""Integration tests for scraper auth strategy usage.

These tests verify that the scraper correctly uses stored auth strategies
during polling (Step 5 of Auth Strategy Discovery).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from custom_components.cable_modem_monitor.core.auth.handler import AuthHandler
from custom_components.cable_modem_monitor.core.auth.types import AuthStrategyType
from custom_components.cable_modem_monitor.core.modem_scraper import ModemScraper


class TestScraperAuthStrategyUsage:
    """Test that scraper uses stored auth strategy during polling."""

    def test_scraper_accepts_auth_strategy_param(self):
        """Scraper accepts auth_strategy parameter."""
        scraper = ModemScraper(
            host="http://192.168.100.1",
            username="admin",
            password="password",
            auth_strategy="basic_http",
        )

        assert scraper._auth_strategy == "basic_http"
        assert scraper._auth_handler is not None
        assert scraper._auth_handler.strategy == AuthStrategyType.BASIC_HTTP

    def test_scraper_accepts_form_config_param(self):
        """Scraper accepts auth_form_config parameter."""
        form_config = {
            "action": "/login",
            "method": "POST",
            "username_field": "user",
            "password_field": "pass",
            "hidden_fields": {"csrf": "token123"},
        }
        scraper = ModemScraper(
            host="http://192.168.100.1",
            username="admin",
            password="password",
            auth_strategy="form_plain",
            auth_form_config=form_config,
        )

        assert scraper._auth_handler.form_config == form_config

    def test_scraper_no_auth_strategy_falls_back_to_parser(self):
        """Without auth_strategy or auth_form_hints, scraper falls back to parser.login().

        NOTE (v3.12.0): Parsers with auth_form_hints use AuthHandler instead of
        parser.login(). This test verifies the fallback for parsers without hints.
        """
        mock_parser = MagicMock()
        mock_parser.login.return_value = (True, "<html>data</html>")
        # Explicitly set no hints to test the parser.login() fallback
        mock_parser.hnap_hints = None
        mock_parser.js_auth_hints = None
        mock_parser.auth_form_hints = None

        scraper = ModemScraper(
            host="http://192.168.100.1",
            username="admin",
            password="password",
            parser=mock_parser,
            auth_strategy=None,  # No stored strategy
        )

        success, html = scraper._login()

        # Should call parser.login() as fallback (no hints)
        mock_parser.login.assert_called_once()
        assert success is True


class TestScraperBasicAuthStrategy:
    """Test scraper with BASIC_HTTP strategy."""

    def test_basic_auth_sets_session_credentials(self, basic_auth_server):
        """Basic auth strategy sets session.auth."""
        scraper = ModemScraper(
            host=basic_auth_server.url,
            username="admin",
            password="password",
            auth_strategy="basic_http",
        )

        success, html = scraper._login()

        assert success is True
        assert scraper.session.auth == ("admin", "password")


class TestScraperFormAuthStrategy:
    """Test scraper with FORM_PLAIN strategy."""

    def test_form_auth_uses_stored_config(self, form_auth_server):
        """Form auth strategy uses stored form config."""
        form_config = {
            "action": "/login",
            "method": "POST",
            "username_field": "username",
            "password_field": "password",
            "hidden_fields": {"csrf_token": "test_token"},
        }

        scraper = ModemScraper(
            host=form_auth_server.url,
            username="admin",
            password="password",
            auth_strategy="form_plain",
            auth_form_config=form_config,
        )

        success, html = scraper._login()

        # Should succeed with form auth
        assert success is True


class TestScraperNoAuthStrategy:
    """Test scraper with NO_AUTH strategy."""

    def test_no_auth_strategy_succeeds(self, http_server):
        """NO_AUTH strategy succeeds without any auth action."""
        scraper = ModemScraper(
            host=http_server.url,
            username=None,
            password=None,
            auth_strategy="no_auth",
        )

        success, html = scraper._login()

        assert success is True


class TestScraperHNAPStrategy:
    """Test scraper with HNAP_SESSION strategy (v3.12.0+).

    HNAP is now handled directly by AuthHandler, not delegated to parser.
    """

    def test_hnap_strategy_uses_auth_handler(self):
        """HNAP strategy uses AuthHandler directly (not parser.login())."""
        mock_parser = MagicMock()
        # _json_builder will be set by AuthHandler if HNAP auth succeeds

        scraper = ModemScraper(
            host="http://192.168.100.1",
            username="admin",
            password="password",
            parser=mock_parser,
            auth_strategy="hnap_session",
        )

        # Auth handler should be configured for HNAP
        assert scraper._auth_handler is not None
        assert scraper._auth_handler.strategy == AuthStrategyType.HNAP_SESSION
        # Parser.login() should NOT be called (auth handled by AuthHandler)


class TestScraperURLTokenStrategy:
    """Test scraper with URL_TOKEN_SESSION strategy (v3.12.0+).

    URL token auth is now handled directly by AuthHandler.
    """

    def test_url_token_strategy_uses_auth_handler(self):
        """URL token strategy uses AuthHandler directly."""
        mock_parser = MagicMock()

        scraper = ModemScraper(
            host="http://192.168.100.1",
            username="admin",
            password="password",
            parser=mock_parser,
            auth_strategy="url_token_session",
        )

        # Auth handler should be configured for URL token
        assert scraper._auth_handler is not None
        assert scraper._auth_handler.strategy == AuthStrategyType.URL_TOKEN_SESSION
        # Parser.login() should NOT be called (auth handled by AuthHandler)


class TestScraperLegacyEntryHandling:
    """Test handling of legacy config entries without auth_strategy."""

    def test_legacy_entry_without_strategy_uses_parser(self):
        """Config entry without auth_strategy falls back to parser.login().

        NOTE (v3.12.0): Parsers with auth_form_hints use AuthHandler instead.
        This test verifies the fallback for parsers without hints.
        """
        mock_parser = MagicMock()
        mock_parser.login.return_value = (True, "<html>data</html>")
        # Explicitly set no hints to test the parser.login() fallback
        mock_parser.hnap_hints = None
        mock_parser.js_auth_hints = None
        mock_parser.auth_form_hints = None

        # Legacy entry: no auth_strategy or auth_form_config
        scraper = ModemScraper(
            host="http://192.168.100.1",
            username="admin",
            password="password",
            parser=mock_parser,
            auth_strategy=None,
            auth_form_config=None,
        )

        success, html = scraper._login()

        # Should use parser.login() for legacy entries without hints
        mock_parser.login.assert_called_once()
        assert success is True

    def test_legacy_entry_no_parser_no_strategy_fails_gracefully(self):
        """Legacy entry without parser or strategy fails gracefully."""
        scraper = ModemScraper(
            host="http://192.168.100.1",
            username="admin",
            password="password",
            parser=None,
            auth_strategy=None,
        )

        success, html = scraper._login()

        # Should fail gracefully
        assert success is False


class TestScraperAuthHandlerIntegration:
    """Test AuthHandler integration with ModemScraper."""

    def test_form_auth_without_config_fails_gracefully(self):
        """Form auth without config returns failure."""
        mock_parser = MagicMock()

        # Create scraper with form auth but no form config
        scraper = ModemScraper(
            host="http://192.168.100.1",
            username="admin",
            password="password",
            parser=mock_parser,
            auth_strategy="form_plain",
            auth_form_config=None,  # Missing config will cause warning
        )

        success, html = scraper._login()

        # Form auth without config should fail (no form_config)
        assert success is False

    def test_auth_handler_initialized_correctly(self):
        """Auth handler is initialized with correct strategy."""
        scraper = ModemScraper(
            host="http://192.168.100.1",
            username="admin",
            password="password",
            auth_strategy="basic_http",
        )

        assert isinstance(scraper._auth_handler, AuthHandler)
        assert scraper._auth_handler.strategy == AuthStrategyType.BASIC_HTTP

    def test_auth_handler_initialized_with_unknown_strategy(self):
        """Unknown strategy string handled gracefully."""
        scraper = ModemScraper(
            host="http://192.168.100.1",
            username="admin",
            password="password",
            auth_strategy="not_a_real_strategy",
        )

        # Should default to UNKNOWN
        assert scraper._auth_handler.strategy == AuthStrategyType.UNKNOWN


class TestScraperNoCredentials:
    """Test scraper behavior when no credentials provided."""

    def test_no_credentials_skips_login(self):
        """Without credentials, _login() returns success immediately."""
        scraper = ModemScraper(
            host="http://192.168.100.1",
            username=None,
            password=None,
            auth_strategy="basic_http",  # Strategy exists but no creds
        )

        success, html = scraper._login()

        # Should return True immediately (skip login)
        assert success is True
        assert html is None

    def test_empty_credentials_skips_login(self):
        """Empty string credentials skip login."""
        scraper = ModemScraper(
            host="http://192.168.100.1",
            username="",
            password="",
            auth_strategy="basic_http",
        )

        success, html = scraper._login()

        # Should return True immediately (skip login)
        assert success is True
        assert html is None

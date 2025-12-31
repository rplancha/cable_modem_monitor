"""Unit tests for connectivity check SSL fallback behavior.

These tests verify that _do_quick_connectivity_check properly falls back
to legacy SSL when modern SSL fails with handshake errors.

Issue #81: The connectivity check was failing for legacy SSL modems because
it used plain requests without LegacySSLAdapter fallback.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
import requests


class TestConnectivityCheckSSLFallback:
    """Tests for SSL fallback in connectivity check.

    Expected behavior:
    1. Try HTTPS with plain requests
    2. SSL handshake fails
    3. Try HTTPS with LegacySSLAdapter
    4. If that works, return (True, None, True)
    """

    def test_connectivity_check_should_fallback_on_ssl_handshake_error(self):
        """Verify connectivity check tries legacy SSL when modern fails."""
        from custom_components.cable_modem_monitor.config_flow import (
            _do_quick_connectivity_check,
        )

        # Create an SSL handshake error
        ssl_error = requests.exceptions.SSLError(
            "HTTPSConnectionPool(host='192.168.100.1', port=443): "
            "Max retries exceeded with url: / "
            "(Caused by SSLError(SSLError(1, '[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] "
            "ssl/tls alert handshake failure (_ssl.c:1032)')))"
        )

        # Mock response for successful legacy SSL connection
        mock_response = MagicMock()
        mock_response.status_code = 200

        # Create a mock session that returns success
        mock_legacy_session = MagicMock()
        mock_legacy_session.get.return_value = mock_response

        with (
            patch("requests.head") as mock_head,
            patch("requests.get") as mock_get,
            patch("requests.Session") as mock_session_class,
        ):
            # Modern SSL fails with handshake error
            mock_head.side_effect = ssl_error
            mock_get.side_effect = ssl_error

            # Legacy SSL session succeeds
            mock_session_class.return_value = mock_legacy_session

            is_reachable, error, legacy_ssl = _do_quick_connectivity_check("https://192.168.100.1")

            # Should succeed with legacy SSL
            assert is_reachable is True, (
                "Connectivity check should succeed after falling back to legacy SSL. " f"Instead got error: {error}"
            )
            assert error is None
            assert legacy_ssl is True, "Should indicate legacy SSL was needed"

    def test_connectivity_check_returns_false_for_non_ssl_errors(self):
        """Verify non-SSL errors still return failure (no false positives)."""
        from custom_components.cable_modem_monitor.config_flow import (
            _do_quick_connectivity_check,
        )

        # Connection refused - not an SSL issue
        connection_error = requests.exceptions.ConnectionError("Connection refused")

        with patch("requests.head") as mock_head, patch("requests.get") as mock_get:
            mock_head.side_effect = connection_error
            mock_get.side_effect = connection_error

            is_reachable, error, legacy_ssl = _do_quick_connectivity_check("https://192.168.100.1")

            # This should correctly return False - connection is actually refused
            assert is_reachable is False
            assert error is not None
            assert legacy_ssl is False

    def test_modern_ssl_success_returns_legacy_false(self):
        """Verify successful modern SSL connection returns legacy_ssl=False."""
        from custom_components.cable_modem_monitor.config_flow import (
            _do_quick_connectivity_check,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("requests.head") as mock_head:
            mock_head.return_value = mock_response

            is_reachable, error, legacy_ssl = _do_quick_connectivity_check("https://192.168.100.1")

            assert is_reachable is True
            assert error is None
            assert legacy_ssl is False, "Modern SSL should not set legacy_ssl=True"


class TestConnectivityCheckHTTPRedirectToHTTPS:
    """Tests for HTTP requests that redirect to HTTPS with legacy SSL.

    Travis's SB8200 redirects HTTP to HTTPS. When this happens:
    1. requests.get("http://...") follows redirect to https://...
    2. HTTPS connection fails with SSL handshake error
    3. Connectivity check moves on to try HTTPS directly, which triggers legacy SSL
    """

    def test_http_with_ssl_error_falls_back_to_https(self):
        """Verify HTTP URL that gets SSL error tries HTTPS with legacy SSL.

        Note: When HTTP redirects to HTTPS and SSL fails, the connectivity
        check will try the HTTPS URL next, which should trigger legacy SSL.
        """
        from custom_components.cable_modem_monitor.config_flow import (
            _do_quick_connectivity_check,
        )

        # SSL error that happens when HTTP redirects to HTTPS
        ssl_error = requests.exceptions.SSLError(
            "HTTPSConnectionPool(host='192.168.100.1', port=443): "
            "Max retries exceeded with url: / "
            "(Caused by SSLError(SSLError(1, '[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] "
            "ssl/tls alert handshake failure (_ssl.c:1032)')))"
        )

        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_legacy_session = MagicMock()
        mock_legacy_session.get.return_value = mock_response

        with (
            patch("requests.head") as mock_head,
            patch("requests.get") as mock_get,
            patch("requests.Session") as mock_session_class,
        ):
            # Both HTTP and HTTPS fail with SSL error (redirect scenario)
            mock_head.side_effect = ssl_error
            mock_get.side_effect = ssl_error

            # Legacy SSL session succeeds
            mock_session_class.return_value = mock_legacy_session

            # Test with bare host (will try https:// first, then http://)
            is_reachable, error, legacy_ssl = _do_quick_connectivity_check("192.168.100.1")

            # Should succeed via legacy SSL on HTTPS URL
            assert is_reachable is True, f"Should succeed with legacy SSL fallback. Error: {error}"
            assert error is None
            assert legacy_ssl is True


class TestConnectivityCheckLogging:
    """Tests for connectivity check logging behavior.

    Verify that log levels are appropriate:
    - INFO: High-level flow (what we're doing, success)
    - DEBUG: Attempt details (fallback attempts, individual failures)
    - ERROR: Only when ALL attempts fail
    - WARNING: Should NOT be used for expected fallback behavior
    """

    @pytest.fixture
    def config_flow_logger(self):
        """Get the config_flow logger for assertions."""
        return logging.getLogger("custom_components.cable_modem_monitor.config_flow")

    def test_successful_connection_logs_at_info_not_warning(self, caplog):
        """Verify successful connection logs at INFO level, not WARNING."""
        from custom_components.cable_modem_monitor.config_flow import (
            _do_quick_connectivity_check,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("requests.head") as mock_head:
            mock_head.return_value = mock_response

            with caplog.at_level(logging.DEBUG):
                is_reachable, error, legacy_ssl = _do_quick_connectivity_check("192.168.100.1")

        assert is_reachable is True

        # Should have INFO success message
        info_messages = [r for r in caplog.records if r.levelno == logging.INFO]
        assert any("Connected to modem" in r.message for r in info_messages), "Should log success at INFO level"

        # Should NOT have WARNING for successful connection
        warning_messages = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert not any(
            "Connected" in r.message for r in warning_messages
        ), "Success should not be logged at WARNING level"

    def test_fallback_attempts_log_at_info_not_warning(self, caplog):
        """Verify fallback attempts (HTTPS fail, HTTP succeed) log at INFO (not WARNING).

        Config flow logs at INFO level so diagnostics are captured without debug mode.
        """
        from custom_components.cable_modem_monitor.config_flow import (
            _do_quick_connectivity_check,
        )

        # HTTPS fails with connection refused (common for HTTP-only modems)
        connection_error = requests.exceptions.ConnectionError("Connection refused")

        mock_response = MagicMock()
        mock_response.status_code = 200

        call_count = 0

        def mock_head_side_effect(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if url.startswith("https://"):
                raise connection_error
            return mock_response

        with patch("requests.head") as mock_head:
            mock_head.side_effect = mock_head_side_effect

            with caplog.at_level(logging.DEBUG):
                is_reachable, error, legacy_ssl = _do_quick_connectivity_check("192.168.100.1")

        assert is_reachable is True

        # HTTPS failure should be logged at INFO (for diagnostics), not WARNING
        warning_messages = [r for r in caplog.records if r.levelno == logging.WARNING]
        https_warnings = [r for r in warning_messages if "HTTPS" in r.message and "error" in r.message.lower()]
        assert (
            len(https_warnings) == 0
        ), f"HTTPS connection errors should be INFO, not WARNING. Found: {[r.message for r in https_warnings]}"

        # Should have INFO messages for the attempts (config flow logs at INFO for diagnostics)
        info_messages = [r for r in caplog.records if r.levelno == logging.INFO]
        assert any("Trying" in r.message for r in info_messages), "Should have INFO messages for connection attempts"

    def test_get_fallback_logs_at_info_not_warning(self, caplog):
        """Verify HEAD->GET fallback logs at INFO (not WARNING), success at INFO.

        Config flow logs at INFO level so diagnostics are captured without debug mode.
        """
        from custom_components.cable_modem_monitor.config_flow import (
            _do_quick_connectivity_check,
        )

        # HEAD fails with connection reset (some modems reject HEAD)
        connection_reset = requests.exceptions.ConnectionError("Connection reset by peer")

        mock_response = MagicMock()
        mock_response.status_code = 200

        with (
            patch("requests.head") as mock_head,
            patch("requests.get") as mock_get,
        ):
            mock_head.side_effect = connection_reset
            mock_get.return_value = mock_response

            with caplog.at_level(logging.DEBUG):
                is_reachable, error, legacy_ssl = _do_quick_connectivity_check("http://192.168.100.1")

        assert is_reachable is True

        # Fallback retry should be at INFO (for diagnostics), not WARNING
        warning_messages = [r for r in caplog.records if r.levelno == logging.WARNING]
        retry_warnings = [r for r in warning_messages if "fallback" in r.message.lower() or "Retrying" in r.message]
        assert (
            len(retry_warnings) == 0
        ), f"Fallback attempts should be INFO, not WARNING. Found: {[r.message for r in retry_warnings]}"

        # Retry message should be at INFO
        info_messages = [r for r in caplog.records if r.levelno == logging.INFO]
        assert any(
            "Retrying" in r.message or "GET" in r.message for r in info_messages
        ), "Should have INFO message for GET retry"

        # Success message should be at INFO and indicate GET fallback
        success_messages = [r for r in info_messages if "Connected" in r.message]
        assert len(success_messages) > 0, "Should have INFO success message"
        assert any(
            "GET fallback" in r.message for r in success_messages
        ), "Success message should indicate GET fallback was used"

    def test_complete_failure_logs_at_error_with_diagnostics(self, caplog):
        """Verify complete failure logs at ERROR with diagnostic details."""
        from custom_components.cable_modem_monitor.config_flow import (
            _do_quick_connectivity_check,
        )

        # All attempts fail
        connection_error = requests.exceptions.ConnectionError("Connection refused")

        with (
            patch("requests.head") as mock_head,
            patch("requests.get") as mock_get,
        ):
            mock_head.side_effect = connection_error
            mock_get.side_effect = connection_error

            with caplog.at_level(logging.DEBUG):
                is_reachable, error, legacy_ssl = _do_quick_connectivity_check("192.168.100.1")

        assert is_reachable is False

        # Should have ERROR message with diagnostic details
        error_messages = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(error_messages) > 0, "Complete failure should log at ERROR level"
        assert any("FAILED" in r.message for r in error_messages), "Error message should indicate failure"
        assert any("Diagnostic" in r.message for r in error_messages), "Error message should include diagnostic details"

    def test_legacy_ssl_success_logs_at_info(self, caplog):
        """Verify legacy SSL success logs at INFO.

        Config flow logs at INFO level so diagnostics are captured without debug mode.
        """
        from custom_components.cable_modem_monitor.config_flow import (
            _do_quick_connectivity_check,
        )

        # SSL handshake error triggers legacy SSL fallback
        ssl_error = requests.exceptions.SSLError("ssl/tls alert handshake failure")

        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_legacy_session = MagicMock()
        mock_legacy_session.get.return_value = mock_response

        with (
            patch("requests.head") as mock_head,
            patch("requests.get") as mock_get,
            patch("requests.Session") as mock_session_class,
        ):
            mock_head.side_effect = ssl_error
            mock_get.side_effect = ssl_error
            mock_session_class.return_value = mock_legacy_session

            with caplog.at_level(logging.DEBUG):
                is_reachable, error, legacy_ssl = _do_quick_connectivity_check("https://192.168.100.1")

        assert is_reachable is True
        assert legacy_ssl is True

        # Legacy SSL success should be at INFO
        info_messages = [r for r in caplog.records if r.levelno == logging.INFO]
        assert any(
            "legacy SSL" in r.message for r in info_messages
        ), "Legacy SSL success should be logged at INFO and mention 'legacy SSL'"

        # Legacy SSL attempt should be at INFO (for diagnostics), not WARNING
        warning_messages = [r for r in caplog.records if r.levelno == logging.WARNING]
        legacy_warnings = [r for r in warning_messages if "legacy" in r.message.lower()]
        assert (
            len(legacy_warnings) == 0
        ), f"Legacy SSL attempts should be INFO, not WARNING. Found: {[r.message for r in legacy_warnings]}"

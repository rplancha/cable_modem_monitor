"""Unit tests for connectivity check SSL fallback behavior.

These tests verify that _do_quick_connectivity_check properly falls back
to legacy SSL when modern SSL fails with handshake errors.

Issue #81: The connectivity check was failing for legacy SSL modems because
it used plain requests without LegacySSLAdapter fallback.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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

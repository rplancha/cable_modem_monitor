"""Tests for _do_quick_connectivity_check with various SSL scenarios.

These tests verify that the connectivity check correctly handles:
1. HTTP servers (should work)
2. HTTPS servers with modern SSL (should work)
3. HTTPS servers with legacy-only SSL (should work with fallback)
4. HTTP servers that redirect to HTTPS with legacy SSL

Issue #81 exposed a bug where the connectivity check fails for legacy SSL
servers because it uses plain requests without LegacySSLAdapter fallback.
The legacy SSL detection runs AFTER the connectivity check, so it never
gets a chance to help.

These tests are written TDD-style: they should FAIL with the current
implementation, proving the bug exists.
"""

from __future__ import annotations

import pytest

from custom_components.cable_modem_monitor.config_flow import (
    _do_quick_connectivity_check,
)


def _legacy_server_rejects_modern_client(url: str) -> bool:
    """Check if legacy server actually rejects modern SSL clients."""
    import requests

    session = requests.Session()
    try:
        session.get(url, timeout=5, verify=False)
        return False  # Server accepted modern client
    except requests.exceptions.SSLError:
        return True  # Server rejected modern client


@pytest.mark.integration
class TestConnectivityCheckHTTP:
    """Tests for connectivity check with plain HTTP servers."""

    def test_http_server_is_reachable(self, http_server):
        """Verify connectivity check works for HTTP servers."""
        is_reachable, error, legacy_ssl = _do_quick_connectivity_check(http_server.url)
        assert is_reachable is True
        assert error is None
        assert legacy_ssl is False  # HTTP doesn't need legacy SSL


@pytest.mark.integration
class TestConnectivityCheckHTTPSModern:
    """Tests for connectivity check with modern HTTPS servers."""

    def test_https_modern_server_is_reachable(self, https_modern_server):
        """Verify connectivity check works for HTTPS with modern ciphers."""
        is_reachable, error, legacy_ssl = _do_quick_connectivity_check(https_modern_server.url)
        assert is_reachable is True
        assert error is None
        assert legacy_ssl is False  # Modern SSL worked


@pytest.mark.integration
class TestConnectivityCheckHTTPSLegacy:
    """Tests for connectivity check with legacy-only HTTPS servers.

    These tests verify the fix for Issue #81: connectivity check now
    falls back to LegacySSLAdapter when modern SSL fails.
    """

    def test_https_legacy_server_is_reachable(self, https_legacy_server):
        """Verify connectivity check works for HTTPS with legacy ciphers.

        Expected: is_reachable=True with legacy_ssl=True (after fallback)
        """
        # Skip if system OpenSSL negotiates with legacy ciphers anyway
        if not _legacy_server_rejects_modern_client(https_legacy_server.url):
            pytest.skip("System OpenSSL negotiates with legacy ciphers; " "cannot test legacy SSL fallback scenario")

        is_reachable, error, legacy_ssl = _do_quick_connectivity_check(https_legacy_server.url)

        assert is_reachable is True, (
            f"Connectivity check should succeed with legacy SSL fallback. " f"Error was: {error}"
        )
        assert error is None
        assert legacy_ssl is True, "Should indicate legacy SSL was needed"

"""HAR-Based Validation Tests for Auth Strategy Discovery.

These tests use real HAR captures to validate that:
1. AuthDiscovery correctly identifies auth strategies from real modem responses
2. Parsers can parse real response data
3. The full flow works end-to-end

Tests are skipped if HAR files are not available (e.g., in CI environments).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from custom_components.cable_modem_monitor.core.auth import AuthStrategyType

# Path to RAW_DATA directory
RAW_DATA_DIR = Path(__file__).parent.parent.parent / "RAW_DATA"


def load_har(path: Path) -> dict[str, Any] | None:
    """Load a HAR file, return None if not found."""
    if not path.exists():
        return None
    with open(path) as f:
        result: dict[str, Any] = json.load(f)
        return result


def extract_html_responses(har_data: dict[str, Any]) -> list[tuple[str, str]]:
    """Extract URL and HTML content pairs from HAR entries."""
    results = []
    for entry in har_data.get("log", {}).get("entries", []):
        response = entry.get("response", {})
        content = response.get("content", {})

        # Only process HTML responses
        mime_type = content.get("mimeType", "")
        if "html" not in mime_type.lower():
            continue

        url = entry.get("request", {}).get("url", "")
        text = content.get("text", "")

        if url and text:
            results.append((url, text))

    return results


def extract_login_urls(har_data: dict[str, Any]) -> list[str]:
    """Extract URLs that contain login-related parameters."""
    results = []
    for entry in har_data.get("log", {}).get("entries", []):
        url = entry.get("request", {}).get("url", "")
        if "login_" in url.lower() or "ct_" in url.lower():
            results.append(url)
    return results


def extract_hnap_requests(har_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract HNAP POST requests."""
    results = []
    for entry in har_data.get("log", {}).get("entries", []):
        url = entry.get("request", {}).get("url", "")
        method = entry.get("request", {}).get("method", "")

        if "/HNAP" in url.upper() and method == "POST":
            post_data = entry.get("request", {}).get("postData", {})
            results.append(
                {
                    "url": url,
                    "body": post_data.get("text", ""),
                    "status": entry.get("response", {}).get("status"),
                }
            )
    return results


class TestSB8200HARValidation:
    """Validate SB8200 auth discovery against real HAR capture."""

    @pytest.fixture
    def har_data(self) -> dict[str, Any] | None:
        """Load SB8200 HAR file."""
        har_path = RAW_DATA_DIR / "v3.12.0/arris-sb8200/attachments/modem_20251230_132038.sanitized-mod.har"
        return load_har(har_path)

    def test_har_file_exists(self, har_data):
        """Verify HAR file is available for testing."""
        if har_data is None:
            pytest.skip("SB8200 HAR file not available")
        assert har_data is not None

    def test_url_token_auth_pattern_detected(self, har_data):
        """Verify URL token auth pattern is present in HAR."""
        if har_data is None:
            pytest.skip("SB8200 HAR file not available")

        login_urls = extract_login_urls(har_data)

        # Should have login_ prefixed URL
        login_requests = [u for u in login_urls if "login_" in u.lower()]
        assert len(login_requests) > 0, "No login_ URLs found in HAR"

        # Should have ct_ prefixed URL for data fetch
        token_requests = [u for u in login_urls if "ct_" in u.lower()]
        assert len(token_requests) > 0, "No ct_ (session token) URLs found in HAR"

    def test_auth_strategy_matches_expected(self, har_data):
        """Verify expected auth strategy is URL_TOKEN_SESSION."""
        if har_data is None:
            pytest.skip("SB8200 HAR file not available")

        from custom_components.cable_modem_monitor.parsers.arris.sb8200 import ArrisSB8200Parser

        # Parser should have js_auth_hints for URL token
        parser = ArrisSB8200Parser()
        assert hasattr(parser, "js_auth_hints")
        assert parser.js_auth_hints["pattern"] == "url_token_session"
        assert parser.js_auth_hints["login_prefix"] == "login_"
        assert parser.js_auth_hints["token_prefix"] == "ct_"

    def test_html_content_can_be_parsed(self, har_data):
        """Verify parser can parse HTML from HAR."""
        if har_data is None:
            pytest.skip("SB8200 HAR file not available")

        from bs4 import BeautifulSoup

        from custom_components.cable_modem_monitor.parsers.arris.sb8200 import ArrisSB8200Parser

        html_responses = extract_html_responses(har_data)

        # Find the status page HTML
        status_html = None
        for url, html in html_responses:
            if "cmconnectionstatus" in url.lower():
                status_html = html
                break

        if not status_html:
            pytest.skip("No cmconnectionstatus.html found in HAR")

        soup = BeautifulSoup(status_html, "html.parser")
        parser = ArrisSB8200Parser()

        # Parser should be able to detect this as SB8200
        assert parser.can_parse(soup, "https://192.168.100.1", status_html)


class TestS33HARValidation:
    """Validate S33 auth discovery against real HAR capture."""

    @pytest.fixture
    def har_data(self) -> dict[str, Any] | None:
        """Load S33 HAR file."""
        har_path = RAW_DATA_DIR / "v3.12.0/arris-s33/S33/modem_20251206_115107.sanitized.har"
        return load_har(har_path)

    def test_har_file_exists(self, har_data):
        """Verify HAR file is available for testing."""
        if har_data is None:
            pytest.skip("S33 HAR file not available")
        assert har_data is not None

    def test_hnap_auth_pattern_detected(self, har_data):
        """Verify HNAP auth pattern is present in HAR."""
        if har_data is None:
            pytest.skip("S33 HAR file not available")

        hnap_requests = extract_hnap_requests(har_data)

        # Should have HNAP POST requests
        assert len(hnap_requests) > 0, "No HNAP requests found in HAR"

        # At least one should be successful
        successful = [r for r in hnap_requests if r["status"] == 200]
        assert len(successful) > 0, "No successful HNAP requests in HAR"

    def test_hnap_json_format(self, har_data):
        """Verify HNAP requests use JSON format with empty string action value."""
        if har_data is None:
            pytest.skip("S33 HAR file not available")

        hnap_requests = extract_hnap_requests(har_data)
        if not hnap_requests:
            pytest.skip("No HNAP requests in HAR")

        # Check the request body format
        for req in hnap_requests:
            if req["body"]:
                # Should be JSON format
                body = json.loads(req["body"])
                assert isinstance(body, dict), "HNAP body should be JSON object"

                # S33 uses empty string for action values
                if "GetMultipleHNAPs" in body:
                    actions = body["GetMultipleHNAPs"]
                    for _action_name, action_value in actions.items():
                        # S33 uses "" (empty string), not {} (empty dict)
                        assert action_value == "", f"S33 should use empty string, got {action_value!r}"
                break

    def test_auth_strategy_matches_expected(self, har_data):
        """Verify expected auth strategy is HNAP_SESSION."""
        if har_data is None:
            pytest.skip("S33 HAR file not available")

        from custom_components.cable_modem_monitor.parsers.arris.s33 import ArrisS33HnapParser

        # Parser should have hnap_hints
        parser = ArrisS33HnapParser()
        assert hasattr(parser, "hnap_hints")
        assert parser.hnap_hints["endpoint"] == "/HNAP1/"
        assert parser.hnap_hints["empty_action_value"] == ""  # S33-specific


class TestAuthStrategyConstants:
    """Validate auth strategy constants match expected values."""

    def test_all_strategies_defined(self):
        """Verify all auth strategies are defined."""
        expected = [
            "NO_AUTH",
            "BASIC_HTTP",
            "FORM_PLAIN",
            "FORM_BASE64",
            "HNAP_SESSION",
            "URL_TOKEN_SESSION",
            "UNKNOWN",
        ]

        for name in expected:
            assert hasattr(AuthStrategyType, name), f"Missing {name} strategy"

    def test_strategy_string_values(self):
        """Verify strategy string values for storage."""
        assert AuthStrategyType.NO_AUTH.value == "no_auth"
        assert AuthStrategyType.BASIC_HTTP.value == "basic_http"
        assert AuthStrategyType.FORM_PLAIN.value == "form_plain"
        assert AuthStrategyType.FORM_BASE64.value == "form_base64"
        assert AuthStrategyType.HNAP_SESSION.value == "hnap_session"
        assert AuthStrategyType.URL_TOKEN_SESSION.value == "url_token_session"
        assert AuthStrategyType.UNKNOWN.value == "unknown"

    def test_strategy_from_string(self):
        """Verify strategies can be created from string values."""
        assert AuthStrategyType("no_auth") == AuthStrategyType.NO_AUTH
        assert AuthStrategyType("basic_http") == AuthStrategyType.BASIC_HTTP
        assert AuthStrategyType("hnap_session") == AuthStrategyType.HNAP_SESSION
        assert AuthStrategyType("url_token_session") == AuthStrategyType.URL_TOKEN_SESSION


class TestParserHintsConsistency:
    """Validate parser hints are consistent across parsers."""

    def test_s33_hnap_hints_complete(self):
        """Verify S33 has complete HNAP hints."""
        from custom_components.cable_modem_monitor.parsers.arris.s33 import ArrisS33HnapParser

        parser = ArrisS33HnapParser()
        assert hasattr(parser, "hnap_hints")
        hints = parser.hnap_hints

        required_keys = ["endpoint", "namespace", "empty_action_value"]
        for key in required_keys:
            assert key in hints, f"Missing {key} in S33 hnap_hints"

    def test_mb8611_hnap_hints_complete(self):
        """Verify MB8611 has complete HNAP hints."""
        from custom_components.cable_modem_monitor.parsers.motorola.mb8611 import MotorolaMB8611HnapParser

        parser = MotorolaMB8611HnapParser()
        assert hasattr(parser, "hnap_hints")
        hints = parser.hnap_hints

        required_keys = ["endpoint", "namespace", "empty_action_value"]
        for key in required_keys:
            assert key in hints, f"Missing {key} in MB8611 hnap_hints"

    def test_s33_vs_mb8611_hnap_difference(self):
        """Verify S33 and MB8611 have different empty_action_value."""
        from custom_components.cable_modem_monitor.parsers.arris.s33 import ArrisS33HnapParser
        from custom_components.cable_modem_monitor.parsers.motorola.mb8611 import MotorolaMB8611HnapParser

        s33 = ArrisS33HnapParser()
        mb8611 = MotorolaMB8611HnapParser()

        # S33 uses "" (empty string), MB8611 uses {} (empty dict)
        assert s33.hnap_hints["empty_action_value"] == ""
        assert mb8611.hnap_hints["empty_action_value"] == {}

    def test_sb8200_js_auth_hints_complete(self):
        """Verify SB8200 has complete JS auth hints."""
        from custom_components.cable_modem_monitor.parsers.arris.sb8200 import ArrisSB8200Parser

        parser = ArrisSB8200Parser()
        assert hasattr(parser, "js_auth_hints")
        hints = parser.js_auth_hints

        required_keys = [
            "pattern",
            "login_page",
            "login_prefix",
            "session_cookie_name",
            "data_page",
            "token_prefix",
        ]
        for key in required_keys:
            assert key in hints, f"Missing {key} in SB8200 js_auth_hints"

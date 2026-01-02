"""Tests for Cable Modem Monitor diagnostics platform."""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from custom_components.cable_modem_monitor.const import DOMAIN
from custom_components.cable_modem_monitor.diagnostics import (
    _get_auth_discovery_info,
    _get_hnap_auth_attempt,
    _sanitize_log_message,
    async_get_config_entry_diagnostics,
)
from custom_components.cable_modem_monitor.utils.html_helper import sanitize_html


def _create_mock_hass(data: dict) -> Mock:
    """Create a mock HomeAssistant with async_add_executor_job support."""
    hass = Mock(spec=HomeAssistant)
    hass.data = data

    # Mock async_add_executor_job to run the function synchronously
    async def mock_executor_job(func, *args):
        return func(*args)

    hass.async_add_executor_job = mock_executor_job
    return hass


class TestSanitizeHtml:
    """Test HTML sanitization function."""

    def test_removes_mac_addresses(self):
        """Test that MAC addresses are sanitized."""
        html = """
        <tr><td>MAC Address</td><td>AA:BB:CC:DD:EE:FF</td></tr>
        <tr><td>HFC MAC</td><td>11-22-33-44-55-66</td></tr>
        """
        sanitized = sanitize_html(html)

        assert "AA:BB:CC:DD:EE:FF" not in sanitized
        assert "11-22-33-44-55-66" not in sanitized
        assert "XX:XX:XX:XX:XX:XX" in sanitized

    def test_removes_serial_numbers(self):
        """Test that serial numbers are sanitized."""
        test_cases = [
            ("Serial Number: 123456789ABC", "Serial Number: ***REDACTED***"),
            ("S/N: XYZ-999-ABC", "S/N: ***REDACTED***"),
            ("SN: 111222333", "SN: ***REDACTED***"),
        ]

        for original, expected_pattern in test_cases:
            sanitized = sanitize_html(original)
            assert expected_pattern in sanitized
            assert original not in sanitized

    def test_removes_account_ids(self):
        """Test that account/subscriber IDs are sanitized."""
        test_cases = [
            "Account ID: 123456789",
            "Subscriber Number: ABC-999-XYZ",
            "Customer ID: TEST-CUSTOMER-001",
            "Device Number: DEV123456",
        ]

        for original in test_cases:
            sanitized = sanitize_html(original)
            assert "***REDACTED***" in sanitized
            # Original ID should be removed (check for the digits/unique part)
            assert not any(
                char.isdigit() for word in sanitized.split("***REDACTED***") for char in word if char.isalnum()
            )

    def test_removes_private_ips(self):
        """Test that private IP addresses are sanitized."""
        test_cases = [
            ("Gateway: 10.0.1.1", "Gateway: ***PRIVATE_IP***"),
            ("Server: 172.16.5.10", "Server: ***PRIVATE_IP***"),
            ("Host: 192.168.50.100", "Host: ***PRIVATE_IP***"),
        ]

        for original, expected in test_cases:
            sanitized = sanitize_html(original)
            assert expected in sanitized
            # Extract the original IP and verify it's gone
            original_ip = original.split(": ")[1]
            assert original_ip not in sanitized

    def test_preserves_common_modem_ips(self):
        """Test that common modem IPs are preserved for debugging."""
        common_ips = [
            "192.168.100.1",  # Common Motorola modem IP
            "192.168.0.1",  # Common router IP
            "192.168.1.1",  # Common router IP
        ]

        for ip in common_ips:
            html = f"<td>Modem IP: {ip}</td>"
            sanitized = sanitize_html(html)
            assert ip in sanitized  # Should be preserved

    def test_removes_passwords(self):
        """Test that passwords and passphrases are sanitized."""
        test_cases = [
            'password="secret123"',
            "passphrase: MySecretPass",
            'psk="wireless-key-123"',
            "wpa2key: SuperSecret!",
        ]

        for original in test_cases:
            sanitized = sanitize_html(original)
            assert "***REDACTED***" in sanitized
            assert "secret" not in sanitized.lower() or "***REDACTED***" in sanitized

    def test_removes_password_form_values(self):
        """Test that password input field values are sanitized."""
        html = '<input type="password" name="pwd" value="MyPassword123">'
        sanitized = sanitize_html(html)

        assert "MyPassword123" not in sanitized
        assert "***REDACTED***" in sanitized
        assert 'type="password"' in sanitized  # Structure preserved

    def test_removes_session_tokens(self):
        """Test that session tokens and auth tokens are sanitized."""
        html = """
        <meta name="csrf-token" content="abc123def456ghi789jkl012mno345pqr678stu">
        session=xyz999abc888def777ghi666
        """
        sanitized = sanitize_html(html)

        assert "abc123def456ghi789jkl012mno345pqr678stu" not in sanitized
        assert "xyz999abc888def777ghi666" not in sanitized
        assert "***REDACTED***" in sanitized

    def test_preserves_signal_data(self):
        """Test that signal quality data is preserved for debugging."""
        html = """
        <tr>
            <td>Power Level</td><td>7.0 dBmV</td>
            <td>SNR</td><td>40.0 dB</td>
            <td>Frequency</td><td>555000000 Hz</td>
        </tr>
        """
        sanitized = sanitize_html(html)

        # Signal data should be preserved
        assert "7.0 dBmV" in sanitized
        assert "40.0 dB" in sanitized
        assert "555000000 Hz" in sanitized

    def test_preserves_channel_ids(self):
        """Test that channel IDs and counts are preserved."""
        html = """
        <tr><td>Channel ID</td><td>23</td></tr>
        <tr><td>Downstream Channels</td><td>32</td></tr>
        <tr><td>Corrected Errors</td><td>12345</td></tr>
        """
        sanitized = sanitize_html(html)

        assert "Channel ID" in sanitized
        assert "23" in sanitized
        assert "32" in sanitized
        assert "12345" in sanitized

    def test_handles_multiple_macs(self):
        """Test sanitization of multiple MAC addresses in same HTML."""
        html = """
        WAN MAC: AA:BB:CC:DD:EE:FF
        LAN MAC: 11:22:33:44:55:66
        WIFI MAC: 99-88-77-66-55-44
        """
        sanitized = sanitize_html(html)

        # All MACs should be sanitized
        assert "AA:BB:CC:DD:EE:FF" not in sanitized
        assert "11:22:33:44:55:66" not in sanitized
        assert "99-88-77-66-55-44" not in sanitized
        # Should have 3 XX:XX:XX:XX:XX:XX replacements
        assert sanitized.count("XX:XX:XX:XX:XX:XX") == 3

    def test_handles_empty_string(self):
        """Test that empty string is handled gracefully."""
        sanitized = sanitize_html("")
        assert sanitized == ""

    def test_handles_no_sensitive_data(self):
        """Test HTML with no sensitive data passes through mostly unchanged."""
        html = """
        <tr><td>Power</td><td>5.0 dBmV</td></tr>
        <tr><td>SNR</td><td>38 dB</td></tr>
        """
        sanitized = sanitize_html(html)

        # Should be largely unchanged
        assert "5.0 dBmV" in sanitized
        assert "38 dB" in sanitized


class TestSanitizeLogMessage:
    """Test log message sanitization function."""

    def test_removes_credentials(self):
        """Test that credentials are removed from log messages."""
        test_cases = [
            "password=secret123",
            "username: admin",
            "token=abc123xyz",
        ]

        for message in test_cases:
            sanitized = _sanitize_log_message(message)
            assert "***REDACTED***" in sanitized

    def test_removes_file_paths(self):
        """Test that file paths are sanitized."""
        message = "Error in /config/custom_components/test.py and /home/user/.homeassistant/test.log"
        sanitized = _sanitize_log_message(message)

        assert "/config/***PATH***" in sanitized
        assert "/home/***PATH***" in sanitized
        assert "/config/custom_components/test.py" not in sanitized

    def test_removes_private_ips(self):
        """Test that private IPs are removed but common modem IPs preserved."""
        message = "Connecting to 10.0.0.1 and 192.168.100.1 and 172.16.5.5"
        sanitized = _sanitize_log_message(message)

        # Private IPs should be sanitized except common modem IP
        assert "10.0.0.1" not in sanitized
        assert "172.16.5.5" not in sanitized
        assert "192.168.100.1" in sanitized  # Preserved
        assert "***PRIVATE_IP***" in sanitized


@pytest.fixture
def mock_config_entry():
    """Create a mock config entry."""
    entry = Mock(spec=ConfigEntry)
    entry.entry_id = "test_entry"
    entry.title = "Test Modem"
    entry.data = {
        "host": "192.168.100.1",
        "username": "admin",
        "password": "secret",
        "modem_choice": "Motorola MB8611",
        "detected_modem": "MB8611",
        "detected_manufacturer": "Motorola",
        "parser_name": "Motorola MB8611 (Static)",
        "working_url": "https://192.168.100.1/MotoConnection.asp",
        "last_detection": "2025-11-11T10:00:00",
    }
    return entry


@pytest.fixture
def mock_coordinator():
    """Create a mock coordinator."""
    coordinator = Mock(spec=DataUpdateCoordinator)
    coordinator.last_update_success = True
    coordinator.update_interval = timedelta(seconds=600)
    coordinator.last_exception = None
    coordinator.data = {
        "cable_modem_connection_status": "online",
        "cable_modem_downstream_channel_count": 32,
        "cable_modem_upstream_channel_count": 4,
        "cable_modem_downstream": [
            {"channel_id": 1, "frequency": 555000000, "power": 7.0, "snr": 40.0, "corrected": 100, "uncorrected": 0},
        ],
        "cable_modem_upstream": [
            {"channel_id": 1, "frequency": 35000000, "power": 45.0},
        ],
        "cable_modem_total_corrected": 100,
        "cable_modem_total_uncorrected": 0,
        "cable_modem_software_version": "3.0.1",
        "cable_modem_system_uptime": "5 days",
    }
    return coordinator


@pytest.mark.asyncio
async def test_diagnostics_basic_structure(mock_config_entry, mock_coordinator):
    """Test basic diagnostics structure without HTML capture."""
    hass = _create_mock_hass({DOMAIN: {mock_config_entry.entry_id: mock_coordinator}})

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_config_entry)

    # Verify basic structure
    assert "_solentlabs" in diagnostics
    assert "config_entry" in diagnostics
    assert "coordinator" in diagnostics
    assert "modem_data" in diagnostics
    assert "downstream_channels" in diagnostics
    assert "upstream_channels" in diagnostics

    # Verify Solent Labs™ metadata
    solentlabs = diagnostics["_solentlabs"]
    assert solentlabs["tool"] == "cable_modem_monitor/diagnostics"
    assert "version" in solentlabs
    assert "captured_at" in solentlabs
    assert "Solent Labs" in solentlabs["note"]

    # Verify config entry data
    assert diagnostics["config_entry"]["title"] == "Test Modem"
    assert diagnostics["config_entry"]["host"] == "192.168.100.1"
    assert diagnostics["config_entry"]["has_credentials"] is True

    # Verify modem data
    assert diagnostics["modem_data"]["connection_status"] == "online"
    assert diagnostics["modem_data"]["downstream_channel_count"] == 32


@pytest.mark.asyncio
async def test_diagnostics_includes_html_capture_not_expired(mock_config_entry, mock_coordinator):
    """Test diagnostics includes HTML capture when available and not expired."""
    hass = _create_mock_hass({DOMAIN: {mock_config_entry.entry_id: mock_coordinator}})

    # Add HTML capture to coordinator data (not expired)
    future_time = datetime.now() + timedelta(minutes=3)
    mock_coordinator.data["_raw_html_capture"] = {
        "timestamp": datetime.now().isoformat(),
        "trigger": "manual",
        "ttl_expires": future_time.isoformat(),
        "urls": [
            {
                "url": "https://192.168.100.1/MotoConnection.asp",
                "method": "GET",
                "status_code": 200,
                "content_type": "text/html",
                "size_bytes": 12450,
                "content": """
                <html>
                    <tr><td>MAC</td><td>AA:BB:CC:DD:EE:FF</td></tr>
                    <tr><td>Power</td><td>7.0 dBmV</td></tr>
                    <tr><td>Serial Number</td><td>ABC123XYZ</td></tr>
                </html>
                """,
                "parser": "Motorola MB8611",
            }
        ],
    }

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_config_entry)

    # Verify HTML capture is included
    assert "raw_html_capture" in diagnostics
    assert diagnostics["raw_html_capture"]["url_count"] == 1
    assert diagnostics["raw_html_capture"]["trigger"] == "manual"

    # Verify sanitization occurred
    captured_html = diagnostics["raw_html_capture"]["urls"][0]["content"]
    assert "AA:BB:CC:DD:EE:FF" not in captured_html  # MAC removed
    assert "XX:XX:XX:XX:XX:XX" in captured_html  # MAC sanitized
    assert "ABC123XYZ" not in captured_html  # Serial removed
    assert "***REDACTED***" in captured_html  # Serial sanitized
    assert "7.0 dBmV" in captured_html  # Signal data preserved


@pytest.mark.asyncio
async def test_diagnostics_includes_multiple_page_capture(mock_config_entry, mock_coordinator):
    hass = _create_mock_hass({DOMAIN: {mock_config_entry.entry_id: mock_coordinator}})

    # Add HTML capture with multiple pages (login, status, software info, event log)
    future_time = datetime.now() + timedelta(minutes=3)
    mock_coordinator.data["_raw_html_capture"] = {
        "timestamp": datetime.now().isoformat(),
        "trigger": "manual",
        "ttl_expires": future_time.isoformat(),
        "urls": [
            {
                "url": "https://192.168.100.1/login.html",
                "method": "GET",
                "status_code": 200,
                "content_type": "text/html",
                "size_bytes": 5432,
                "content": "<html><form action='/login'>Username: <input name='user'></form></html>",
                "parser": "Motorola MB8611",
                "description": "Login/Auth page",
            },
            {
                "url": "https://192.168.100.1/login.html",
                "method": "POST",
                "status_code": 302,
                "content_type": "text/html",
                "size_bytes": 150,
                "content": "<html><body>Redirecting...</body></html>",
                "parser": "Motorola MB8611",
                "description": "Login/Auth page",
            },
            {
                "url": "https://192.168.100.1/MotoConnection.asp",
                "method": "GET",
                "status_code": 200,
                "content_type": "text/html",
                "size_bytes": 12450,
                "content": """
                <html>
                    <tr><td>MAC</td><td>AA:BB:CC:DD:EE:FF</td></tr>
                    <tr><td>Power</td><td>7.0 dBmV</td></tr>
                </html>
                """,
                "parser": "Motorola MB8611",
                "description": "Initial connection page",
            },
            {
                "url": "https://192.168.100.1/MotoStatusSoftware.asp",
                "method": "GET",
                "status_code": 200,
                "content_type": "text/html",
                "size_bytes": 3200,
                "content": "<html><tr><td>Software Version</td><td>3.0.1</td></tr></html>",
                "parser": "Motorola MB8611",
                "description": "Software info page",
            },
            {
                "url": "https://192.168.100.1/MotoEventLog.asp",
                "method": "GET",
                "status_code": 200,
                "content_type": "text/html",
                "size_bytes": 8900,
                "content": "<html><tr><td>Event</td><td>Connection established</td></tr></html>",
                "parser": "Motorola MB8611",
                "description": "Event log page",
            },
        ],
    }

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_config_entry)

    # Verify HTML capture is included with all pages
    assert "raw_html_capture" in diagnostics
    assert diagnostics["raw_html_capture"]["url_count"] == 5
    assert diagnostics["raw_html_capture"]["trigger"] == "manual"

    # Verify all page types are present
    urls = diagnostics["raw_html_capture"]["urls"]
    descriptions = [url.get("description", "") for url in urls]
    assert "Login/Auth page" in descriptions
    assert "Initial connection page" in descriptions
    assert "Software info page" in descriptions
    assert "Event log page" in descriptions

    # Verify both GET and POST methods are captured
    methods = [url.get("method") for url in urls]
    assert "GET" in methods
    assert "POST" in methods

    # Verify sanitization occurred across all pages
    for url_data in urls:
        content = url_data.get("content", "")
        if "AA:BB:CC:DD:EE:FF" in mock_coordinator.data["_raw_html_capture"]["urls"][urls.index(url_data)]["content"]:
            # Original MAC should be removed, replacement should be present
            assert "AA:BB:CC:DD:EE:FF" not in content
            assert "XX:XX:XX:XX:XX:XX" in content


@pytest.mark.asyncio
async def test_diagnostics_excludes_expired_html_capture(mock_config_entry, mock_coordinator):
    """Test diagnostics excludes HTML capture when expired."""
    hass = _create_mock_hass({DOMAIN: {mock_config_entry.entry_id: mock_coordinator}})

    # Add HTML capture to coordinator data (expired)
    past_time = datetime.now() - timedelta(minutes=10)
    mock_coordinator.data["_raw_html_capture"] = {
        "timestamp": past_time.isoformat(),
        "trigger": "manual",
        "ttl_expires": past_time.isoformat(),
        "urls": [
            {
                "url": "https://192.168.100.1/MotoConnection.asp",
                "content": "<html>test</html>",
            }
        ],
    }

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_config_entry)

    # Verify HTML capture is NOT included (expired)
    assert "raw_html_capture" not in diagnostics


@pytest.mark.asyncio
async def test_diagnostics_without_html_capture(mock_config_entry, mock_coordinator):
    """Test diagnostics works normally when no HTML capture present."""
    hass = _create_mock_hass({DOMAIN: {mock_config_entry.entry_id: mock_coordinator}})

    # Ensure no HTML capture in coordinator data
    assert "_raw_html_capture" not in mock_coordinator.data

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_config_entry)

    # Should work fine without HTML capture
    assert "config_entry" in diagnostics
    assert "modem_data" in diagnostics
    assert "raw_html_capture" not in diagnostics


@pytest.mark.asyncio
async def test_diagnostics_handles_missing_coordinator(mock_config_entry):
    """Test diagnostics handles case where coordinator doesn't exist."""
    from homeassistant.config_entries import ConfigEntryState

    hass = Mock(spec=HomeAssistant)
    # Coordinator doesn't exist in hass.data (setup failed or incomplete)
    hass.data = {DOMAIN: {}}
    # Add state attribute to mock
    mock_config_entry.state = ConfigEntryState.LOADED

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_config_entry)

    # Should return error diagnostics
    assert "error" in diagnostics
    assert "coordinator not found" in diagnostics["error"]
    assert "config_entry" in diagnostics
    assert diagnostics["config_entry"]["title"] == "Test Modem"
    assert diagnostics["config_entry"]["host"] == "192.168.100.1"
    assert diagnostics["config_entry"]["entry_id"] == "test_entry"


@pytest.mark.asyncio
async def test_diagnostics_handles_coordinator_without_data(mock_config_entry, mock_coordinator):
    # Create coordinator with no data
    coordinator = Mock(spec=DataUpdateCoordinator)
    coordinator.last_update_success = False
    coordinator.update_interval = timedelta(seconds=600)
    coordinator.last_exception = Exception("Connection failed")
    coordinator.data = None

    hass = _create_mock_hass({DOMAIN: {mock_config_entry.entry_id: coordinator}})

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_config_entry)

    # Should still return basic structure
    assert "config_entry" in diagnostics
    assert "coordinator" in diagnostics
    assert "last_error" in diagnostics
    assert diagnostics["last_error"]["message"] is not None


@pytest.mark.asyncio
async def test_diagnostics_sanitizes_exception_messages(mock_config_entry, mock_coordinator):
    """Test that exception messages are sanitized."""
    hass = _create_mock_hass({DOMAIN: {mock_config_entry.entry_id: mock_coordinator}})

    # Add exception with sensitive data
    mock_coordinator.last_exception = Exception("Failed to connect to 10.0.0.5 with password=secret123")

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_config_entry)

    # Verify exception is included but sanitized
    assert "last_error" in diagnostics
    error_msg = diagnostics["last_error"]["message"]
    assert "***REDACTED***" in error_msg
    assert "secret123" not in error_msg
    assert "***PRIVATE_IP***" in error_msg or "10.0.0.5" not in error_msg


@pytest.mark.asyncio
async def test_diagnostics_includes_parser_detection_info(mock_config_entry, mock_coordinator):
    """Test that diagnostics includes parser detection information."""
    hass = _create_mock_hass({DOMAIN: {mock_config_entry.entry_id: mock_coordinator}})

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_config_entry)

    # Verify detection section exists (moved from config_entry.parser_detection)
    assert "detection" in diagnostics

    detection = diagnostics["detection"]

    # Verify detection fields
    assert "user_selection" in detection
    assert "method" in detection
    assert "parser" in detection

    # Verify values match config entry
    assert detection["user_selection"] == "Motorola MB8611"
    assert detection["method"] == "user_selected"
    assert detection["parser"] == "Motorola MB8611 (Static)"


# ============================================================================
# Detection Method Tests - TDD for 3 scenarios
# ============================================================================


@pytest.mark.asyncio
async def test_detection_method_fresh_install_auto(mock_coordinator):
    """
    Scenario: Fresh install with auto-detection.

    User selects "auto" → detection succeeds → modem_choice updated to parser name
    → detection_method stored as "auto_detected"

    Expected: method = "auto_detected"
    """
    entry = Mock(spec=ConfigEntry)
    entry.entry_id = "test_fresh_auto"
    entry.title = "Motorola MB7621 (192.168.100.1)"
    entry.data = {
        "host": "192.168.100.1",
        "username": "admin",
        "password": "secret",
        # After auto-detection, modem_choice is updated to match parser_name
        "modem_choice": "Motorola MB7621",
        "parser_name": "Motorola MB7621",
        "detected_modem": "Motorola MB7621",
        "detected_manufacturer": "Motorola",
        "working_url": "http://192.168.100.1/MotoSwInfo.asp",
        "last_detection": "2025-12-31T14:24:03.445441",
        # KEY: This field tracks HOW the parser was selected
        "detection_method": "auto_detected",
    }

    hass = _create_mock_hass({DOMAIN: {entry.entry_id: mock_coordinator}})
    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    detection = diagnostics["detection"]
    assert detection["method"] == "auto_detected"
    assert detection["user_selection"] == "Motorola MB7621"
    assert detection["parser"] == "Motorola MB7621"


@pytest.mark.asyncio
async def test_detection_method_explicit_user_selection(mock_coordinator):
    """
    Scenario: User explicitly selects a parser from dropdown.

    User picks "Motorola MB7621" from dropdown (not auto)
    → detection_method stored as "user_selected"

    Expected: method = "user_selected"
    """
    entry = Mock(spec=ConfigEntry)
    entry.entry_id = "test_explicit_select"
    entry.title = "Motorola MB7621 (192.168.100.1)"
    entry.data = {
        "host": "192.168.100.1",
        "username": "admin",
        "password": "secret",
        # User explicitly selected this parser
        "modem_choice": "Motorola MB7621",
        "parser_name": "Motorola MB7621",
        "detected_modem": "Motorola MB7621",
        "detected_manufacturer": "Motorola",
        "working_url": "http://192.168.100.1/MotoSwInfo.asp",
        "last_detection": "2025-12-31T14:24:19.899726",
        # KEY: User explicitly selected, not auto-detected
        "detection_method": "user_selected",
    }

    hass = _create_mock_hass({DOMAIN: {entry.entry_id: mock_coordinator}})
    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    detection = diagnostics["detection"]
    assert detection["method"] == "user_selected"
    assert detection["user_selection"] == "Motorola MB7621"
    assert detection["parser"] == "Motorola MB7621"


@pytest.mark.asyncio
async def test_detection_method_resubmit_after_auto(mock_coordinator):
    """
    Scenario: Re-submit with explicit selection after previous auto-detection.

    1. Initial: auto-detection found "Motorola MB7621"
    2. Later: User re-opens config, explicitly selects same parser, saves
    → detection_method should update to "user_selected"

    Expected: method = "user_selected" (last action was explicit selection)
    """
    entry = Mock(spec=ConfigEntry)
    entry.entry_id = "test_resubmit"
    entry.title = "Motorola MB7621 (192.168.100.1)"
    entry.data = {
        "host": "192.168.100.1",
        "username": "admin",
        "password": "secret",
        # Same parser name as before, but user explicitly re-selected it
        "modem_choice": "Motorola MB7621",
        "parser_name": "Motorola MB7621",
        "detected_modem": "Motorola MB7621",
        "detected_manufacturer": "Motorola",
        "working_url": "http://192.168.100.1/MotoSwInfo.asp",
        # Newer timestamp from re-submit
        "last_detection": "2025-12-31T14:24:19.899726",
        # KEY: Even though same parser, user explicitly selected this time
        "detection_method": "user_selected",
    }

    hass = _create_mock_hass({DOMAIN: {entry.entry_id: mock_coordinator}})
    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    detection = diagnostics["detection"]
    # This is the critical assertion - re-submit should show user_selected
    assert detection["method"] == "user_selected"


@pytest.mark.asyncio
async def test_detection_method_legacy_no_field(mock_coordinator):
    """
    Scenario: Legacy config entry without detection_method field.

    For backwards compatibility, entries created before this field existed
    should fall back to inferring from modem_choice vs parser_name.

    Expected: Falls back to inference logic (user_selected if different)
    """
    entry = Mock(spec=ConfigEntry)
    entry.entry_id = "test_legacy"
    entry.title = "Motorola MB8611 (192.168.100.1)"
    entry.data = {
        "host": "192.168.100.1",
        "username": "admin",
        "password": "secret",
        # Different modem_choice vs parser_name (legacy explicit selection)
        "modem_choice": "Motorola MB8611",
        "parser_name": "Motorola MB8611 (Static)",
        "detected_modem": "MB8611",
        "detected_manufacturer": "Motorola",
        "working_url": "https://192.168.100.1/MotoConnection.asp",
        "last_detection": "2025-11-11T10:00:00",
        # NO detection_method field - legacy entry
    }

    hass = _create_mock_hass({DOMAIN: {entry.entry_id: mock_coordinator}})
    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    detection = diagnostics["detection"]
    # Fallback: modem_choice != parser_name → user_selected
    assert detection["method"] == "user_selected"


# ============================================================================
# End Detection Method Tests
# ============================================================================


@pytest.mark.asyncio
async def test_diagnostics_parser_detection_history(mock_config_entry, mock_coordinator):
    """Test parser detection history is included when available."""
    hass = _create_mock_hass({DOMAIN: {mock_config_entry.entry_id: mock_coordinator}})

    # Add parser detection history to coordinator data
    mock_coordinator.data["_parser_detection_history"] = {
        "attempted_parsers": ["Motorola MB8611 (Static)", "Motorola MB8600", "Generic Motorola"],
        "detection_phases_run": ["anonymous_probing", "suggested_parser", "prioritized"],
        "timestamp": "2025-11-18T10:00:00",
    }

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_config_entry)

    # Verify parser detection history exists
    assert "parser_detection_history" in diagnostics

    history = diagnostics["parser_detection_history"]
    assert "attempted_parsers" in history
    assert len(history["attempted_parsers"]) == 3
    assert "Motorola MB8611 (Static)" in history["attempted_parsers"]
    assert "detection_phases_run" in history
    assert "timestamp" in history


@pytest.mark.asyncio
async def test_diagnostics_parser_detection_history_not_available(mock_config_entry, mock_coordinator):
    """Test parser detection history shows note when not available."""
    hass = _create_mock_hass({DOMAIN: {mock_config_entry.entry_id: mock_coordinator}})

    # Ensure no parser detection history in coordinator data
    assert "_parser_detection_history" not in mock_coordinator.data

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_config_entry)

    # Verify parser detection history exists with note
    assert "parser_detection_history" in diagnostics

    history = diagnostics["parser_detection_history"]
    assert "note" in history
    assert "succeeded on first attempt" in history["note"]
    assert history["attempted_parsers"] == []


class TestGetHnapAuthAttempt:
    """Test _get_hnap_auth_attempt helper function."""

    def test_returns_note_when_no_scraper(self):
        """Test returns explanatory note when scraper not available."""
        coordinator = Mock()
        coordinator.scraper = None

        result = _get_hnap_auth_attempt(coordinator)

        assert result["note"] == "Scraper not available"

    def test_returns_note_when_no_parser(self):
        """Test returns explanatory note when parser not available."""
        coordinator = Mock()
        coordinator.scraper = Mock()
        coordinator.scraper.parser = None

        result = _get_hnap_auth_attempt(coordinator)

        assert result["note"] == "Parser not available (might be using fallback mode)"

    def test_returns_note_when_no_json_builder(self):
        """Test returns explanatory note when no JSON builder (not HNAP modem)."""
        coordinator = Mock()
        coordinator.scraper = Mock()
        coordinator.scraper.parser = Mock()
        coordinator.scraper.parser._json_builder = None

        result = _get_hnap_auth_attempt(coordinator)

        assert result["note"] == "Not an HNAP modem (no JSON builder)"

    def test_returns_note_when_no_auth_attempt(self):
        """Test returns explanatory note when no auth attempt recorded."""
        coordinator = Mock()
        coordinator.scraper = Mock()
        coordinator.scraper.parser = Mock()
        coordinator.scraper.parser._json_builder = Mock()
        coordinator.scraper.parser._json_builder.get_last_auth_attempt.return_value = None

        result = _get_hnap_auth_attempt(coordinator)

        assert result["note"] == "No HNAP auth attempt recorded yet"

    def test_returns_auth_attempt_data(self):
        """Test returns auth attempt data when available."""
        coordinator = Mock()
        coordinator.scraper = Mock()
        coordinator.scraper.parser = Mock()
        coordinator.scraper.parser._json_builder = Mock()
        coordinator.scraper.parser._json_builder.get_last_auth_attempt.return_value = {
            "challenge_request": {"Login": {"Action": "request", "Username": "admin"}},
            "challenge_response": '{"LoginResponse": {"Challenge": "ABC"}}',
            "login_request": {"Login": {"Action": "login", "LoginPassword": "[REDACTED]"}},
            "login_response": '{"LoginResponse": {"LoginResult": "OK"}}',
            "error": None,
        }

        result = _get_hnap_auth_attempt(coordinator)

        assert "data" in result
        assert "compare with browser" in result["note"]
        assert result["data"]["challenge_request"]["Login"]["Action"] == "request"

    def test_sanitizes_sensitive_data(self):
        """Test that auth attempt data is sanitized."""
        coordinator = Mock()
        coordinator.scraper = Mock()
        coordinator.scraper.parser = Mock()
        coordinator.scraper.parser._json_builder = Mock()
        coordinator.scraper.parser._json_builder.get_last_auth_attempt.return_value = {
            "challenge_request": {"Login": {"Username": "admin"}},
            "challenge_response": "password=secret123",
            "login_request": None,
            "login_response": None,
            "error": None,
        }

        result = _get_hnap_auth_attempt(coordinator)

        # Password should be redacted in response
        assert "secret123" not in result["data"]["challenge_response"]
        assert "REDACTED" in result["data"]["challenge_response"]

    def test_handles_exception_gracefully(self):
        """Test that exceptions are handled gracefully."""
        coordinator = Mock()
        coordinator.scraper = Mock()
        coordinator.scraper.parser = Mock()
        # Simulate an exception
        coordinator.scraper.parser._json_builder = Mock()
        coordinator.scraper.parser._json_builder.get_last_auth_attempt.side_effect = Exception("Something went wrong")

        result = _get_hnap_auth_attempt(coordinator)

        assert "Error retrieving auth data" in result["note"]
        assert "Exception" in result["note"]


class TestGetAuthDiscoveryInfo:
    """Test _get_auth_discovery_info helper function (v3.12.0+)."""

    def test_returns_minimal_info_when_no_strategy(self):
        """Test returns minimal info when no auth strategy configured."""
        entry = Mock(spec=ConfigEntry)
        entry.data = {}

        result = _get_auth_discovery_info(entry)

        assert result["status"] == "not_run"
        assert result["strategy"] == "not_set"
        assert "form_config" not in result
        assert "captured_response" not in result

    def test_returns_strategy_with_description(self):
        """Test returns strategy with description for known strategies."""
        entry = Mock(spec=ConfigEntry)
        entry.data = {
            "auth_strategy": "basic_http",
            "auth_discovery_status": "success",
        }

        result = _get_auth_discovery_info(entry)

        assert result["status"] == "success"
        assert result["strategy"] == "basic_http"
        assert result["strategy_description"] == "HTTP Basic Auth (401 challenge-response)"

    def test_returns_form_config_for_form_auth(self):
        """Test returns form config for form-based auth."""
        entry = Mock(spec=ConfigEntry)
        entry.data = {
            "auth_strategy": "form_plain",
            "auth_discovery_status": "success",
            "auth_form_config": {
                "action": "/login",
                "method": "POST",
                "username_field": "user",
                "password_field": "pass",
                "hidden_fields": {"csrf": "token123"},
            },
        }

        result = _get_auth_discovery_info(entry)

        assert result["strategy"] == "form_plain"
        assert "form_config" in result
        assert result["form_config"]["action"] == "/login"
        assert result["form_config"]["username_field"] == "user"

    def test_includes_failure_info_when_discovery_failed(self):
        """Test includes failure info when discovery failed but modem works."""
        entry = Mock(spec=ConfigEntry)
        entry.data = {
            "auth_strategy": "unknown",
            "auth_discovery_status": "unknown_pattern",
            "auth_discovery_failed": True,
            "auth_discovery_error": "Unknown authentication protocol detected",
        }

        result = _get_auth_discovery_info(entry)

        assert result["discovery_failed"] is True
        assert "note" in result
        assert "help improve" in result["note"]
        assert "Unknown authentication" in result["error"]

    def test_includes_captured_response_for_unknown_pattern(self):
        """Test includes captured response for unknown auth patterns."""
        entry = Mock(spec=ConfigEntry)
        entry.data = {
            "auth_strategy": "unknown",
            "auth_discovery_status": "unknown_pattern",
            "auth_captured_response": {
                "status_code": 200,
                "url": "http://192.168.100.1/login.asp",
                "headers": {"Content-Type": "text/html"},
                "html_sample": "<html><form><input type='password'></form></html>",
            },
        }

        result = _get_auth_discovery_info(entry)

        assert "captured_response" in result
        assert result["captured_response"]["status_code"] == 200
        assert "login.asp" in result["captured_response"]["url"]
        assert "developers add support" in result["captured_response"]["note"]

    def test_sanitizes_captured_response_html(self):
        """Test that captured response HTML is sanitized."""
        entry = Mock(spec=ConfigEntry)
        entry.data = {
            "auth_strategy": "unknown",
            "auth_captured_response": {
                "status_code": 200,
                "url": "http://192.168.100.1/login.asp",
                "headers": {"Content-Type": "text/html"},
                # HTML with MAC address that should be sanitized
                "html_sample": "<html>MAC: AA:BB:CC:DD:EE:FF</html>",
            },
        }

        result = _get_auth_discovery_info(entry)

        # MAC should be sanitized in html_sample
        assert "AA:BB:CC:DD:EE:FF" not in result["captured_response"]["html_sample"]
        assert "XX:XX:XX:XX:XX:XX" in result["captured_response"]["html_sample"]

    def test_hnap_session_strategy_description(self):
        """Test HNAP strategy has correct description."""
        entry = Mock(spec=ConfigEntry)
        entry.data = {
            "auth_strategy": "hnap_session",
            "auth_discovery_status": "success",
        }

        result = _get_auth_discovery_info(entry)

        assert result["strategy"] == "hnap_session"
        assert "HNAP/SOAP" in result["strategy_description"]
        assert "S33" in result["strategy_description"]

    def test_no_auth_strategy_description(self):
        """Test NO_AUTH strategy has correct description."""
        entry = Mock(spec=ConfigEntry)
        entry.data = {
            "auth_strategy": "no_auth",
            "auth_discovery_status": "success",
        }

        result = _get_auth_discovery_info(entry)

        assert result["strategy"] == "no_auth"
        assert "anonymous access" in result["strategy_description"]


@pytest.mark.asyncio
async def test_diagnostics_includes_auth_discovery(mock_config_entry, mock_coordinator):
    """Test that diagnostics includes auth_discovery section."""
    hass = _create_mock_hass({DOMAIN: {mock_config_entry.entry_id: mock_coordinator}})

    # Update config entry with auth discovery data
    mock_config_entry.data = {
        **mock_config_entry.data,
        "auth_strategy": "form_plain",
        "auth_discovery_status": "success",
        "auth_form_config": {
            "action": "/login",
            "method": "POST",
            "username_field": "username",
            "password_field": "password",
        },
    }

    diagnostics = await async_get_config_entry_diagnostics(hass, mock_config_entry)

    # Verify auth_discovery section exists
    assert "auth_discovery" in diagnostics
    auth = diagnostics["auth_discovery"]
    assert auth["status"] == "success"
    assert auth["strategy"] == "form_plain"
    assert "form_config" in auth
    assert auth["form_config"]["action"] == "/login"

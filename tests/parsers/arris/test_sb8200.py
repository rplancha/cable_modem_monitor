"""Tests for the ARRIS SB8200 parser."""

import os

import pytest
from bs4 import BeautifulSoup

from custom_components.cable_modem_monitor.parsers.arris.sb8200 import ArrisSB8200Parser
from custom_components.cable_modem_monitor.parsers.base_parser import ModemCapability


@pytest.fixture
def sb8200_html():
    """Load SB8200 HTML fixture (from Tim's fallback capture)."""
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "sb8200", "root.html")
    with open(fixture_path) as f:
        return f.read()


@pytest.fixture
def sb8200_alt_html():
    """Load SB8200 alternative HTML fixture (original)."""
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "sb8200", "cmconnectionstatus.html")
    # This fixture uses Windows-1252 encoding (copyright symbol)
    with open(fixture_path, encoding="cp1252") as f:
        return f.read()


@pytest.fixture
def sb8200_product_info_html():
    """Load SB8200 product info page (cmswinfo.html)."""
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "sb8200", "cmswinfo.html")
    with open(fixture_path) as f:
        return f.read()


class TestSB8200ParserDetection:
    """Test parser detection logic."""

    def test_can_parse_with_model_span(self, sb8200_html):
        """Test detection via model number span."""
        soup = BeautifulSoup(sb8200_html, "html.parser")
        assert ArrisSB8200Parser.can_parse(soup, "http://192.168.100.1/", sb8200_html)

    def test_can_parse_alt_fixture(self, sb8200_alt_html):
        """Test detection on alternative fixture."""
        soup = BeautifulSoup(sb8200_alt_html, "html.parser")
        assert ArrisSB8200Parser.can_parse(soup, "http://192.168.100.1/cmconnectionstatus.html", sb8200_alt_html)

    def test_parser_metadata(self):
        """Test parser metadata is correct."""
        from custom_components.cable_modem_monitor.parsers.base_parser import ParserStatus

        assert ArrisSB8200Parser.name == "ARRIS SB8200"
        assert ArrisSB8200Parser.manufacturer == "ARRIS"
        assert "SB8200" in ArrisSB8200Parser.models
        assert ArrisSB8200Parser.docsis_version == "3.1"
        assert ArrisSB8200Parser.status == ParserStatus.VERIFIED
        # Also test the verified property via an instance
        parser = ArrisSB8200Parser()
        assert parser.verified is True


class TestSB8200ParserCapabilities:
    """Test parser capabilities declaration."""

    def test_has_downstream_capability(self):
        """Test downstream channels capability."""
        assert ArrisSB8200Parser.has_capability(ModemCapability.DOWNSTREAM_CHANNELS)

    def test_has_upstream_capability(self):
        """Test upstream channels capability."""
        assert ArrisSB8200Parser.has_capability(ModemCapability.UPSTREAM_CHANNELS)

    def test_has_ofdm_downstream_capability(self):
        """Test OFDM downstream capability (DOCSIS 3.1)."""
        assert ArrisSB8200Parser.has_capability(ModemCapability.OFDM_DOWNSTREAM)

    def test_has_ofdm_upstream_capability(self):
        """Test OFDM upstream capability (DOCSIS 3.1)."""
        assert ArrisSB8200Parser.has_capability(ModemCapability.OFDM_UPSTREAM)

    def test_no_restart_capability(self):
        """Test that restart is NOT supported."""
        assert not ArrisSB8200Parser.has_capability(ModemCapability.RESTART)

    def test_has_uptime_capability(self):
        """Test uptime capability (from cmswinfo.html)."""
        assert ArrisSB8200Parser.has_capability(ModemCapability.SYSTEM_UPTIME)

    def test_has_version_capabilities(self):
        """Test hardware/software version capabilities."""
        assert ArrisSB8200Parser.has_capability(ModemCapability.SOFTWARE_VERSION)
        assert ArrisSB8200Parser.has_capability(ModemCapability.HARDWARE_VERSION)


class TestSB8200DownstreamParsing:
    """Test downstream channel parsing."""

    def test_downstream_channel_count(self, sb8200_html):
        """Test correct number of downstream channels parsed."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_html, "html.parser")
        data = parser.parse(soup)

        assert "downstream" in data
        # SB8200 has 32 downstream channels (31 QAM256 + 1 OFDM)
        assert len(data["downstream"]) == 32

    def test_first_downstream_channel(self, sb8200_html):
        """Test first downstream channel values."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_html, "html.parser")
        data = parser.parse(soup)

        # First channel in Tim's capture is channel 19
        first_ds = data["downstream"][0]
        assert first_ds["channel_id"] == "19"
        assert first_ds["frequency"] == 435000000  # 435 MHz
        assert first_ds["modulation"] == "QAM256"
        assert first_ds["channel_type"] == "qam"  # Derived from modulation
        assert first_ds["power"] == 5.5
        assert first_ds["snr"] == 43.3
        assert first_ds["corrected"] == 158
        assert first_ds["uncorrected"] == 604

    def test_ofdm_downstream_channel(self, sb8200_html):
        """Test OFDM downstream channel (channel 33)."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_html, "html.parser")
        data = parser.parse(soup)

        # Find the OFDM channel (modulation "Other")
        ofdm_channels = [ch for ch in data["downstream"] if ch.get("modulation") == "Other"]
        assert len(ofdm_channels) == 1

        ofdm = ofdm_channels[0]
        assert ofdm["channel_id"] == "33"
        assert ofdm["frequency"] == 524000000  # 524 MHz
        assert ofdm.get("is_ofdm") is True
        assert ofdm["channel_type"] == "ofdm"  # Derived from modulation="Other" (issue #87)
        assert ofdm["power"] == 6.3
        assert ofdm["snr"] == 41.8


class TestSB8200UpstreamParsing:
    """Test upstream channel parsing."""

    def test_upstream_channel_count(self, sb8200_html):
        """Test correct number of upstream channels parsed."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_html, "html.parser")
        data = parser.parse(soup)

        assert "upstream" in data
        # SB8200 has 3 upstream channels (2 SC-QAM + 1 OFDM)
        assert len(data["upstream"]) == 3

    def test_first_upstream_channel(self, sb8200_html):
        """Test first upstream channel values."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_html, "html.parser")
        data = parser.parse(soup)

        first_us = data["upstream"][0]
        assert first_us["channel_id"] == "4"
        assert first_us["channel_type"] == "SC-QAM Upstream"
        assert first_us["frequency"] == 37000000  # 37 MHz
        assert first_us["width"] == 6400000  # 6.4 MHz
        assert first_us["power"] == 42.0

    def test_ofdm_upstream_channel(self, sb8200_html):
        """Test OFDM upstream channel."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_html, "html.parser")
        data = parser.parse(soup)

        # Find the OFDM upstream channel
        ofdm_channels = [ch for ch in data["upstream"] if "OFDM" in ch.get("channel_type", "")]
        assert len(ofdm_channels) == 1

        ofdm = ofdm_channels[0]
        assert ofdm["channel_id"] == "1"
        assert ofdm["channel_type"] == "OFDM Upstream"
        assert ofdm["frequency"] == 6025000  # 6.025 MHz
        assert ofdm["width"] == 17200000  # 17.2 MHz
        assert ofdm.get("is_ofdm") is True


class TestSB8200SystemInfo:
    """Test system info parsing."""

    def test_system_info_exists(self, sb8200_html):
        """Test that system_info is returned."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_html, "html.parser")
        data = parser.parse(soup)

        assert "system_info" in data
        assert isinstance(data["system_info"], dict)

    def test_current_time_parsed(self, sb8200_html):
        """Test current time is parsed from systime element."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_html, "html.parser")
        data = parser.parse(soup)

        # Check that current_time was parsed (may contain IPv6 placeholder)
        if "current_time" in data["system_info"]:
            assert "2025" in data["system_info"]["current_time"]


class TestSB8200Login:
    """Test login behavior - unit tests without network."""

    def test_login_no_credentials_succeeds(self):
        """Test that login with no credentials returns (True, None)."""
        parser = ArrisSB8200Parser()
        result = parser.login(None, "http://192.168.100.1", None, None)
        assert result == (True, None)

    def test_login_empty_credentials_succeeds(self):
        """Test that login with empty string credentials returns (True, None)."""
        parser = ArrisSB8200Parser()
        result = parser.login(None, "http://192.168.100.1", "", "")
        assert result == (True, None)


class TestSB8200AlternativeFixture:
    """Test parsing with alternative fixture."""

    def test_downstream_parsing_alt(self, sb8200_alt_html):
        """Test downstream parsing with alternative fixture."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_alt_html, "html.parser")
        data = parser.parse(soup)

        assert "downstream" in data
        assert len(data["downstream"]) == 32

    def test_upstream_parsing_alt(self, sb8200_alt_html):
        """Test upstream parsing with alternative fixture."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_alt_html, "html.parser")
        data = parser.parse(soup)

        assert "upstream" in data
        assert len(data["upstream"]) == 3


class TestSB8200ProductInfoParsing:
    """Test product info parsing from cmswinfo.html."""

    def test_parse_uptime(self, sb8200_product_info_html):
        """Test uptime parsing from product info page."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_product_info_html, "html.parser")
        info = parser._parse_product_info(soup)

        assert "system_uptime" in info
        # Stored as raw string for display (matches other parsers)
        assert info["system_uptime"] == "8 days 01h:16m:13s.00"

    def test_parse_hardware_version(self, sb8200_product_info_html):
        """Test hardware version parsing."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_product_info_html, "html.parser")
        info = parser._parse_product_info(soup)

        assert "hardware_version" in info
        assert info["hardware_version"] == "6"

    def test_parse_software_version(self, sb8200_product_info_html):
        """Test software version parsing."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_product_info_html, "html.parser")
        info = parser._parse_product_info(soup)

        assert "software_version" in info
        assert "AB01.01.009" in info["software_version"]

    def test_parse_docsis_version(self, sb8200_product_info_html):
        """Test DOCSIS version parsing."""
        parser = ArrisSB8200Parser()
        soup = BeautifulSoup(sb8200_product_info_html, "html.parser")
        info = parser._parse_product_info(soup)

        assert "docsis_version" in info
        assert info["docsis_version"] == "Docsis 3.1"


class TestSB8200UptimeParsing:
    """Test uptime string parsing."""

    def test_parse_uptime_with_days(self):
        """Test parsing uptime with days."""
        parser = ArrisSB8200Parser()
        result = parser._parse_uptime("8 days 01h:16m:13s.00")
        assert result == 695773  # 8*86400 + 1*3600 + 16*60 + 13

    def test_parse_uptime_one_day(self):
        """Test parsing uptime with singular 'day'."""
        parser = ArrisSB8200Parser()
        result = parser._parse_uptime("1 day 00h:00m:00s.00")
        assert result == 86400

    def test_parse_uptime_no_days(self):
        """Test parsing uptime without days prefix."""
        parser = ArrisSB8200Parser()
        result = parser._parse_uptime("12h:30m:45s")
        assert result == 45045  # 12*3600 + 30*60 + 45

    def test_parse_uptime_invalid(self):
        """Test parsing invalid uptime returns None."""
        parser = ArrisSB8200Parser()
        result = parser._parse_uptime("invalid format")
        assert result is None

    def test_parse_uptime_empty(self):
        """Test parsing empty string returns None."""
        parser = ArrisSB8200Parser()
        result = parser._parse_uptime("")
        assert result is None


class TestSB8200AuthConfig:
    """Test authentication configuration."""

    def test_auth_config_type(self):
        """Test that auth config uses URL_TOKEN_SESSION strategy."""
        from custom_components.cable_modem_monitor.core.auth import AuthStrategyType

        assert ArrisSB8200Parser.auth_config.strategy == AuthStrategyType.URL_TOKEN_SESSION

    def test_auth_config_defaults(self):
        """Test auth config has correct defaults for SB8200."""
        config = ArrisSB8200Parser.auth_config
        assert config.login_page == "/cmconnectionstatus.html"
        assert config.data_page == "/cmconnectionstatus.html"
        assert config.login_prefix == "login_"
        assert config.token_prefix == "ct_"
        assert config.session_cookie_name == "sessionId"
        assert config.success_indicator == "Downstream Bonded Channels"


class TestSB8200AuthenticatedUrls:
    """Test authenticated URL building."""

    def test_build_url_without_session_token(self):
        """Test URL building when no session token is set."""
        parser = ArrisSB8200Parser()
        url = parser._build_authenticated_url("https://192.168.100.1", "/cmswinfo.html")
        assert url == "https://192.168.100.1/cmswinfo.html"

    def test_build_url_with_session_token(self):
        """Test URL building when session token is set."""
        parser = ArrisSB8200Parser()
        parser._session_token = "testtoken123"
        url = parser._build_authenticated_url("https://192.168.100.1", "/cmswinfo.html")
        assert url == "https://192.168.100.1/cmswinfo.html?ct_testtoken123"


class TestSB8200VariantTracking:
    """Test auth variant tracking for diagnostics."""

    def test_no_credentials_sets_http_variant(self):
        """Test that no credentials sets HTTP no-auth variant."""
        parser = ArrisSB8200Parser()
        success, _ = parser.login(None, "http://192.168.100.1", None, None)

        assert success is True
        assert parser._auth_variant == ArrisSB8200Parser.VARIANT_HTTP_NO_AUTH

    def test_no_credentials_https_sets_http_variant_with_warning(self):
        """Test that no credentials on HTTPS still sets HTTP variant (with warning)."""
        parser = ArrisSB8200Parser()
        success, _ = parser.login(None, "https://192.168.100.1", None, None)

        assert success is True
        assert parser._auth_variant == ArrisSB8200Parser.VARIANT_HTTP_NO_AUTH

    def test_variant_constants_defined(self):
        """Test that all variant constants are defined."""
        assert ArrisSB8200Parser.VARIANT_HTTP_NO_AUTH == "http_no_auth"
        assert ArrisSB8200Parser.VARIANT_HTTPS_TOKEN_SESSION == "https_token_session"
        assert ArrisSB8200Parser.VARIANT_HTTPS_NO_AUTH_FALLBACK == "https_no_auth_fallback"


class TestSB8200AuthVariantInDiagnostics:
    """Test auth variant appears in parsed output."""

    def test_auth_variant_in_system_info(self, sb8200_html):
        """Test that auth variant is included in system_info."""
        parser = ArrisSB8200Parser()
        # Set variant as if login was called
        parser._auth_variant = ArrisSB8200Parser.VARIANT_HTTP_NO_AUTH

        soup = BeautifulSoup(sb8200_html, "html.parser")
        data = parser.parse(soup)

        assert "auth_variant" in data["system_info"]
        assert data["system_info"]["auth_variant"] == "http_no_auth"

    def test_no_auth_variant_when_not_set(self, sb8200_html):
        """Test that auth_variant is not in system_info if not set."""
        parser = ArrisSB8200Parser()
        # Don't set _auth_variant

        soup = BeautifulSoup(sb8200_html, "html.parser")
        data = parser.parse(soup)

        # Should not be present if not set
        assert parser._auth_variant is None
        assert "auth_variant" not in data["system_info"]


class TestSB8200UnauthenticatedFallback:
    """Test unauthenticated fallback behavior."""

    def test_fallback_method_exists(self):
        """Test that unauthenticated fallback method exists."""
        parser = ArrisSB8200Parser()
        assert hasattr(parser, "_try_unauthenticated_fetch")
        assert callable(parser._try_unauthenticated_fetch)

    def test_fallback_returns_none_on_failure(self):
        """Test that fallback returns None when fetch fails."""
        from unittest.mock import MagicMock

        parser = ArrisSB8200Parser()
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Connection failed")

        result = parser._try_unauthenticated_fetch(mock_session, "https://192.168.100.1")

        assert result is None

    def test_fallback_returns_none_when_no_channel_data(self):
        """Test that fallback returns None when response lacks channel data."""
        from unittest.mock import MagicMock

        parser = ArrisSB8200Parser()
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>Login page</html>"  # No channel data
        mock_session.get.return_value = mock_response

        result = parser._try_unauthenticated_fetch(mock_session, "https://192.168.100.1")

        assert result is None

    def test_fallback_returns_html_when_successful(self):
        """Test that fallback returns HTML when channel data found."""
        from unittest.mock import MagicMock

        parser = ArrisSB8200Parser()
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>Downstream Bonded Channels data</html>"
        mock_session.get.return_value = mock_response

        result = parser._try_unauthenticated_fetch(mock_session, "https://192.168.100.1")

        assert result == mock_response.text


class TestSB8200HttpsAuthFlow:
    """Test HTTPS authentication flow with credentials."""

    def test_login_with_credentials_uses_auth_strategy(self):
        """Test that login with credentials calls the auth strategy."""
        from unittest.mock import MagicMock, patch

        parser = ArrisSB8200Parser()
        mock_session = MagicMock()
        mock_session.cookies = MagicMock()
        mock_session.cookies.get.return_value = "session123"

        with patch("custom_components.cable_modem_monitor.parsers.arris.sb8200.AuthFactory") as mock_factory:
            mock_strategy = MagicMock()
            mock_strategy.login.return_value = (True, "<html>Downstream Bonded Channels</html>")
            mock_factory.get_strategy.return_value = mock_strategy

            success, html = parser.login(mock_session, "https://192.168.100.1", "admin", "password123")

            # Verify AuthFactory was called with correct strategy type
            from custom_components.cable_modem_monitor.core.auth import AuthStrategyType

            mock_factory.get_strategy.assert_called_once_with(AuthStrategyType.URL_TOKEN_SESSION)
            # Verify strategy.login was called
            mock_strategy.login.assert_called_once()
            assert success is True
            assert html is not None
            assert "Downstream Bonded Channels" in html

    def test_login_success_stores_session_token(self):
        """Test that successful login stores the session token."""
        from unittest.mock import MagicMock, patch

        parser = ArrisSB8200Parser()
        mock_session = MagicMock()
        mock_session.cookies = MagicMock()
        mock_session.cookies.get.return_value = "stored_token_abc123"

        with patch("custom_components.cable_modem_monitor.parsers.arris.sb8200.AuthFactory") as mock_factory:
            mock_strategy = MagicMock()
            mock_strategy.login.return_value = (True, "<html>Downstream Bonded Channels</html>")
            mock_factory.get_strategy.return_value = mock_strategy

            parser.login(mock_session, "https://192.168.100.1", "admin", "password")

            # Verify session token was stored
            assert parser._session_token == "stored_token_abc123"
            mock_session.cookies.get.assert_called_with("sessionId")

    def test_login_success_sets_https_variant(self):
        """Test that successful HTTPS login sets the correct variant."""
        from unittest.mock import MagicMock, patch

        parser = ArrisSB8200Parser()
        mock_session = MagicMock()
        mock_session.cookies = MagicMock()
        mock_session.cookies.get.return_value = "token123"

        with patch("custom_components.cable_modem_monitor.parsers.arris.sb8200.AuthFactory") as mock_factory:
            mock_strategy = MagicMock()
            mock_strategy.login.return_value = (True, "<html>Downstream Bonded Channels</html>")
            mock_factory.get_strategy.return_value = mock_strategy

            parser.login(mock_session, "https://192.168.100.1", "admin", "password")

            assert parser._auth_variant == ArrisSB8200Parser.VARIANT_HTTPS_TOKEN_SESSION

    def test_login_failure_triggers_fallback(self):
        """Test that auth failure triggers unauthenticated fallback."""
        from unittest.mock import MagicMock, patch

        parser = ArrisSB8200Parser()
        mock_session = MagicMock()
        mock_session.cookies = MagicMock()
        mock_session.cookies.get.return_value = None

        # Mock auth strategy to fail (but not with 401)
        with patch("custom_components.cable_modem_monitor.parsers.arris.sb8200.AuthFactory") as mock_factory:
            mock_strategy = MagicMock()
            mock_strategy.login.return_value = (False, "Connection error")
            mock_factory.get_strategy.return_value = mock_strategy

            # Mock fallback to succeed
            with patch.object(parser, "_try_unauthenticated_fetch") as mock_fallback:
                mock_fallback.return_value = "<html>Downstream Bonded Channels data</html>"

                success, html = parser.login(mock_session, "https://192.168.100.1", "admin", "password")

                # Fallback should have been called
                mock_fallback.assert_called_once_with(mock_session, "https://192.168.100.1")
                assert success is True
                assert html is not None
                assert "Downstream Bonded Channels" in html

    def test_login_failure_fallback_sets_variant(self):
        """Test that successful fallback sets the fallback variant."""
        from unittest.mock import MagicMock, patch

        parser = ArrisSB8200Parser()
        mock_session = MagicMock()
        mock_session.cookies = MagicMock()
        mock_session.cookies.get.return_value = None

        with patch("custom_components.cable_modem_monitor.parsers.arris.sb8200.AuthFactory") as mock_factory:
            mock_strategy = MagicMock()
            mock_strategy.login.return_value = (False, "Auth failed")
            mock_factory.get_strategy.return_value = mock_strategy

            with patch.object(parser, "_try_unauthenticated_fetch") as mock_fallback:
                mock_fallback.return_value = "<html>Downstream Bonded Channels</html>"

                parser.login(mock_session, "https://192.168.100.1", "admin", "password")

                assert parser._auth_variant == ArrisSB8200Parser.VARIANT_HTTPS_NO_AUTH_FALLBACK

    def test_login_401_does_not_fallback(self):
        """Test that 401 error does not trigger fallback (indicates wrong creds)."""
        from unittest.mock import MagicMock, patch

        parser = ArrisSB8200Parser()
        mock_session = MagicMock()
        mock_session.cookies = MagicMock()
        mock_session.cookies.get.return_value = None

        with patch("custom_components.cable_modem_monitor.parsers.arris.sb8200.AuthFactory") as mock_factory:
            mock_strategy = MagicMock()
            # 401 in the response message indicates auth rejection
            mock_strategy.login.return_value = (False, "401 Unauthorized")
            mock_factory.get_strategy.return_value = mock_strategy

            with patch.object(parser, "_try_unauthenticated_fetch") as mock_fallback:
                success, response = parser.login(mock_session, "https://192.168.100.1", "admin", "wrongpassword")

                # Fallback should NOT be called for 401
                mock_fallback.assert_not_called()
                assert success is False
                assert response is not None
                assert "401" in response

    def test_login_failure_fallback_fails_returns_original_error(self):
        """Test that when fallback also fails, original error is returned."""
        from unittest.mock import MagicMock, patch

        parser = ArrisSB8200Parser()
        mock_session = MagicMock()
        mock_session.cookies = MagicMock()
        mock_session.cookies.get.return_value = None

        with patch("custom_components.cable_modem_monitor.parsers.arris.sb8200.AuthFactory") as mock_factory:
            mock_strategy = MagicMock()
            mock_strategy.login.return_value = (False, "Network timeout")
            mock_factory.get_strategy.return_value = mock_strategy

            with patch.object(parser, "_try_unauthenticated_fetch") as mock_fallback:
                mock_fallback.return_value = None  # Fallback fails

                success, response = parser.login(mock_session, "https://192.168.100.1", "admin", "password")

                assert success is False
                assert response == "Network timeout"


class TestSB8200MultiPageFetch:
    """Test multi-page fetch in parse() method."""

    def test_parse_fetches_product_info_when_session_provided(self, sb8200_html, sb8200_product_info_html):
        """Test that parse() fetches cmswinfo.html when session is available."""
        from unittest.mock import MagicMock

        parser = ArrisSB8200Parser()
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = sb8200_product_info_html
        mock_session.get.return_value = mock_response

        soup = BeautifulSoup(sb8200_html, "html.parser")
        data = parser.parse(soup, session=mock_session, base_url="https://192.168.100.1")

        # Verify session.get was called for cmswinfo.html
        mock_session.get.assert_called_once()
        call_args = mock_session.get.call_args
        assert "/cmswinfo.html" in call_args[0][0]

        # Verify product info was merged
        assert "system_uptime" in data["system_info"]
        assert "hardware_version" in data["system_info"]
        assert "software_version" in data["system_info"]

    def test_parse_uses_session_token_for_product_info(self, sb8200_html, sb8200_product_info_html):
        """Test that parse() uses session token when fetching cmswinfo.html."""
        from unittest.mock import MagicMock

        parser = ArrisSB8200Parser()
        parser._session_token = "mytoken456"

        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = sb8200_product_info_html
        mock_session.get.return_value = mock_response

        soup = BeautifulSoup(sb8200_html, "html.parser")
        parser.parse(soup, session=mock_session, base_url="https://192.168.100.1")

        # Verify URL contains the session token
        call_args = mock_session.get.call_args
        assert "ct_mytoken456" in call_args[0][0]

    def test_parse_handles_product_info_fetch_failure(self, sb8200_html):
        """Test that parse() continues gracefully if cmswinfo.html fetch fails."""
        from unittest.mock import MagicMock

        parser = ArrisSB8200Parser()
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Connection refused")

        soup = BeautifulSoup(sb8200_html, "html.parser")
        data = parser.parse(soup, session=mock_session, base_url="https://192.168.100.1")

        # Parse should still succeed with channel data
        assert "downstream" in data
        assert len(data["downstream"]) == 32
        # Product info fields should be absent
        assert "system_uptime" not in data.get("system_info", {})

    def test_parse_without_session_skips_product_info_fetch(self, sb8200_html):
        """Test that parse() without session doesn't try to fetch cmswinfo.html."""
        parser = ArrisSB8200Parser()

        soup = BeautifulSoup(sb8200_html, "html.parser")
        data = parser.parse(soup)  # No session, no base_url

        # Should still parse channel data
        assert "downstream" in data
        assert len(data["downstream"]) == 32


# Note: Integration tests for auth are in tests/integration/test_sb8200_auth.py
# Note: CSRF token extraction is now handled by UrlTokenSessionStrategy

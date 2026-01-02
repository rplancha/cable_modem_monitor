"""Tests for the Technicolor CGA2121 parser."""

from __future__ import annotations

import os
from unittest.mock import Mock

import pytest
from bs4 import BeautifulSoup

from custom_components.cable_modem_monitor.parsers.technicolor.cga2121 import (
    TechnicolorCGA2121Parser,
)


@pytest.fixture
def st_docsis_html():
    """Load st_docsis.html fixture."""
    path = os.path.join(os.path.dirname(__file__), "fixtures", "cga2121", "st_docsis.html")
    with open(path, encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def logon_html():
    """Load logon.html fixture from extended folder."""
    path = os.path.join(os.path.dirname(__file__), "fixtures", "cga2121", "extended", "logon.html")
    with open(path, encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def parser():
    """Create a CGA2121 parser instance."""
    return TechnicolorCGA2121Parser()


class TestMetadata:
    """Test parser metadata."""

    def test_parser_name(self, parser):
        """Test parser name."""
        assert parser.name == "Technicolor CGA2121"

    def test_manufacturer(self, parser):
        """Test manufacturer."""
        assert parser.manufacturer == "Technicolor"

    def test_models(self, parser):
        """Test models list."""
        assert "CGA2121" in parser.models

    def test_docsis_version(self, parser):
        """Test DOCSIS version."""
        assert parser.docsis_version == "3.0"

    def test_fixtures_path(self, parser):
        """Test fixtures path exists."""
        assert parser.fixtures_path is not None
        assert "cga2121" in parser.fixtures_path


class TestDetection:
    """Test modem detection."""

    def test_can_parse_by_model_name(self, st_docsis_html):
        """Test detection by CGA2121 model name in HTML."""
        soup = BeautifulSoup(st_docsis_html, "html.parser")
        result = TechnicolorCGA2121Parser.can_parse(soup, "http://192.168.100.1/st_docsis.html", st_docsis_html)
        assert result is True

    def test_can_parse_by_url_and_branding(self, st_docsis_html):
        """Test detection by URL pattern and Technicolor branding."""
        # Remove CGA2121 from HTML but keep Technicolor
        modified_html = st_docsis_html.replace("CGA2121", "GATEWAY")
        soup = BeautifulSoup(modified_html, "html.parser")
        result = TechnicolorCGA2121Parser.can_parse(soup, "http://192.168.100.1/st_docsis.html", modified_html)
        assert result is True

    def test_does_not_match_other_modem(self):
        """Test that parser doesn't match other modems."""
        html = "<html><title>Other Modem</title><body>Some content</body></html>"
        soup = BeautifulSoup(html, "html.parser")
        result = TechnicolorCGA2121Parser.can_parse(soup, "http://192.168.100.1/status.html", html)
        assert result is False


class TestParsing:
    """Test parser functionality."""

    def test_downstream_channels(self, parser, st_docsis_html):
        """Test parsing of downstream channels."""
        soup = BeautifulSoup(st_docsis_html, "html.parser")
        data = parser.parse(soup)
        downstream = data["downstream"]

        assert len(downstream) == 24

        # Check first channel
        assert downstream[0]["channel_id"] == 1
        assert downstream[0]["modulation"] == "QAM256"
        assert downstream[0]["snr"] == 42.3
        assert downstream[0]["power"] == 10.4

        # Check last channel
        assert downstream[23]["channel_id"] == 24
        assert downstream[23]["modulation"] == "QAM256"
        assert downstream[23]["snr"] == 39.4
        assert downstream[23]["power"] == 7.7

    def test_upstream_channels(self, parser, st_docsis_html):
        """Test parsing of upstream channels."""
        soup = BeautifulSoup(st_docsis_html, "html.parser")
        data = parser.parse(soup)
        upstream = data["upstream"]

        assert len(upstream) == 4

        # Check first channel
        assert upstream[0]["channel_id"] == 1
        assert upstream[0]["modulation"] == "QAM64"
        assert upstream[0]["power"] == 43.7

        # Check last channel
        assert upstream[3]["channel_id"] == 4
        assert upstream[3]["modulation"] == "QAM64"
        assert upstream[3]["power"] == 43.5

    def test_system_info(self, parser, st_docsis_html):
        """Test parsing of system info."""
        soup = BeautifulSoup(st_docsis_html, "html.parser")
        data = parser.parse(soup)
        system_info = data["system_info"]

        # Check that basic info is parsed
        assert system_info.get("operational_status") == "Operational"
        assert system_info.get("downstream_channel_count") == 24
        assert system_info.get("upstream_channel_count") == 4

    def test_parse_empty_html_returns_empty(self, parser):
        """Test parsing empty HTML returns empty lists."""
        soup = BeautifulSoup("<html><body></body></html>", "html.parser")
        data = parser.parse(soup)

        assert data["downstream"] == []
        assert data["upstream"] == []
        assert data["system_info"] == {}


class TestAuthHints:
    """Test auth discovery hints (v3.12.0+)."""

    def test_has_auth_form_hints(self, parser):
        """Test parser has auth_form_hints for non-standard form fields."""
        hints = TechnicolorCGA2121Parser.auth_form_hints
        assert hints.get("username_field") == "username_login"
        assert hints.get("password_field") == "password_login"

    def test_login_returns_default(self, parser):
        """Test login() uses base class default (auth handled by AuthDiscovery)."""
        session = Mock()
        success, html = parser.login(session, "http://192.168.100.1", "admin", "password")
        # Base class default returns (True, None)
        assert success is True
        assert html is None


class TestFixtures:
    """Test fixture file existence."""

    def test_fixture_file_exists(self):
        """Test that required fixture files exist."""
        fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures", "cga2121")
        assert os.path.exists(fixtures_dir)
        assert os.path.exists(os.path.join(fixtures_dir, "st_docsis.html"))
        assert os.path.exists(os.path.join(fixtures_dir, "metadata.yaml"))
        assert os.path.exists(os.path.join(fixtures_dir, "README.md"))

    def test_extended_fixture_exists(self):
        """Test that extended fixture files exist."""
        extended_dir = os.path.join(os.path.dirname(__file__), "fixtures", "cga2121", "extended")
        assert os.path.exists(extended_dir)
        assert os.path.exists(os.path.join(extended_dir, "logon.html"))

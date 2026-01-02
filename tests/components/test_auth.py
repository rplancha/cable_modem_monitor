from __future__ import annotations

from custom_components.cable_modem_monitor.core.auth.handler import AuthHandler
from custom_components.cable_modem_monitor.core.modem_scraper import ModemScraper
from custom_components.cable_modem_monitor.parsers.motorola.mb7621 import MotorolaMB7621Parser
from custom_components.cable_modem_monitor.parsers.technicolor.tc4400 import TechnicolorTC4400Parser


class TestAuth:
    """Test the authentication system.

    NOTE: As of v3.12.0, authentication is handled by AuthHandler.
    Parsers with auth_form_hints use AuthHandler for form-based auth.
    Parsers without auth_form_hints fall back to parser.login().
    """

    def test_form_auth_uses_parser_hints(self, mocker):
        """Test form-based authentication uses parser's auth_form_hints (v3.12.0+).

        When a parser has auth_form_hints defined, the scraper creates a temporary
        AuthHandler to handle authentication instead of calling parser.login().
        """
        scraper = ModemScraper("192.168.100.1", "admin", "password", parser=[MotorolaMB7621Parser])
        # _fetch_data now returns (html, url, parser_class)
        mocker.patch.object(
            scraper, "_fetch_data", return_value=("<html></html>", "http://192.168.100.1", MotorolaMB7621Parser)
        )
        mocker.patch.object(scraper, "_detect_parser", return_value=MotorolaMB7621Parser())

        # Mock AuthHandler.authenticate to verify it's called instead of parser.login()
        mock_auth = mocker.patch.object(AuthHandler, "authenticate", return_value=(True, None))

        # parser.login should NOT be called when auth_form_hints exist
        mock_parser_login = mocker.patch.object(MotorolaMB7621Parser, "login", return_value=(True, None))

        scraper.get_modem_data()

        # AuthHandler.authenticate should be called (via the temp handler created for hints)
        mock_auth.assert_called_once()
        # parser.login should NOT be called
        mock_parser_login.assert_not_called()

    def test_basic_auth_uses_parser_login(self, mocker):
        """Test that parsers without auth_form_hints fall back to parser.login()."""
        scraper = ModemScraper("192.168.100.1", "admin", "password", parser=[TechnicolorTC4400Parser])
        # _fetch_data now returns (html, url, parser_class)
        mocker.patch.object(
            scraper, "_fetch_data", return_value=("<html></html>", "http://192.168.100.1", TechnicolorTC4400Parser)
        )
        mocker.patch.object(scraper, "_detect_parser", return_value=TechnicolorTC4400Parser())

        # TC4400 has no auth_form_hints, so should fall back to parser.login()
        mock_login = mocker.patch.object(TechnicolorTC4400Parser, "login", return_value=(True, None))
        scraper.get_modem_data()

        mock_login.assert_called_once()

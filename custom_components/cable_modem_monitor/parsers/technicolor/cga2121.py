"""Parser for Technicolor CGA2121 cable modem."""

from __future__ import annotations

import logging

from bs4 import BeautifulSoup

from custom_components.cable_modem_monitor.lib.utils import extract_float, extract_number

from ..base_parser import ModemCapability, ModemParser, ParserStatus

_LOGGER = logging.getLogger(__name__)


class TechnicolorCGA2121Parser(ModemParser):
    """Parser for Technicolor CGA2121 cable modem (Telia Finland)."""

    name = "Technicolor CGA2121"
    manufacturer = "Technicolor"
    models = ["CGA2121"]

    # Parser status
    status = ParserStatus.AWAITING_VERIFICATION
    verification_source = None

    # Device metadata
    release_date = "2015"
    docsis_version = "3.0"
    fixtures_path = "tests/parsers/technicolor/fixtures/cga2121"

    # Auth handled by AuthDiscovery (v3.12.0+) - hints for non-standard form fields
    auth_form_hints = {
        "username_field": "username_login",
        "password_field": "password_login",
    }

    url_patterns = [
        {"path": "/st_docsis.html", "auth_method": "form", "auth_required": True},
    ]

    # Capabilities - CGA2121 provides limited data (no frequency, no codewords)
    capabilities = {
        ModemCapability.DOWNSTREAM_CHANNELS,
        ModemCapability.UPSTREAM_CHANNELS,
    }

    # login() not needed - uses base class default (AuthDiscovery handles auth)

    @classmethod
    def can_parse(cls, soup: BeautifulSoup, url: str, html: str) -> bool:
        """
        Detect if this is a Technicolor CGA2121 modem.

        Detection criteria:
        1. URL contains "st_docsis.html"
        2. HTML contains "CGA2121" model identifier
        3. Page title is "DOCSIS Status"
        """
        # Primary detection: Model name in HTML
        if "CGA2121" in html:
            _LOGGER.debug("CGA2121 detected by model name in HTML")
            return True

        # Secondary detection: URL pattern + Technicolor branding
        if "st_docsis.html" in url.lower():
            title_tag = soup.find("title")
            has_docsis_title = title_tag and "DOCSIS Status" in title_tag.get_text()
            has_technicolor = "Technicolor" in html
            if has_docsis_title and has_technicolor:
                _LOGGER.debug("CGA2121 detected by URL + Technicolor branding")
                return True

        return False

    def parse(self, soup: BeautifulSoup, session=None, base_url=None) -> dict:
        """Parse all data from the CGA2121 modem."""
        # Check if we have the DOCSIS status page with channel data
        # If not (e.g., we got a login page), fetch st_docsis.html
        has_channel_headers = soup.find("h2", string=lambda t: t and "Downstream Channels" in t) or soup.find(
            "span", {"data-i18n": "ds_link_downstream_channels"}
        )

        if not has_channel_headers and session and base_url:
            _LOGGER.debug("No channel headers found, fetching st_docsis.html for channel data")
            try:
                docsis_response = session.get(f"{base_url}/st_docsis.html", timeout=10)
                if docsis_response.status_code == 200:
                    soup = BeautifulSoup(docsis_response.text, "html.parser")
                    _LOGGER.debug("Fetched st_docsis.html (%d bytes)", len(docsis_response.text))
                else:
                    _LOGGER.warning("Failed to fetch st_docsis.html: status %d", docsis_response.status_code)
            except Exception as e:
                _LOGGER.error("Failed to fetch st_docsis.html: %s", e)

        downstream_channels = self._parse_downstream(soup)
        upstream_channels = self._parse_upstream(soup)
        system_info = self._parse_system_info(soup)

        return {
            "downstream": downstream_channels,
            "upstream": upstream_channels,
            "system_info": system_info,
        }

    def _find_channel_tbody(self, soup: BeautifulSoup, section_name: str, i18n_key: str) -> BeautifulSoup | None:
        """Find the tbody element for a channel section by header text or i18n key."""
        # Look for header containing section name
        header = None
        for h2 in soup.find_all("h2"):
            if section_name in h2.get_text():
                header = h2
                break

        # Try finding by data-i18n attribute as fallback
        if not header:
            header = soup.find("span", {"data-i18n": i18n_key})

        if not header:
            _LOGGER.warning("CGA2121: %s section not found", section_name)
            return None

        # Find the parent panel and then the table
        panel = header.find_parent("div", class_="panel")
        if not panel:
            _LOGGER.warning("CGA2121: %s panel not found", section_name)
            return None

        tables = panel.find_all("table", class_="rsp-table")
        if not tables:
            _LOGGER.warning("CGA2121: %s table not found", section_name)
            return None

        # Use the last table (the active one, not commented)
        tbody = tables[-1].find("tbody")
        if not tbody:
            _LOGGER.warning("CGA2121: %s tbody not found", section_name)
            return None

        return tbody

    def _parse_downstream(self, soup: BeautifulSoup) -> list[dict]:
        """Parse downstream channel data from CGA2121."""
        channels: list[dict] = []

        try:
            tbody = self._find_channel_tbody(soup, "Downstream Channels", "ds_link_downstream_channels")
            if not tbody:
                return channels

            for row in tbody.find_all("tr"):
                cols = row.find_all("td")
                if len(cols) >= 4:
                    channels.append(
                        {
                            "channel_id": extract_number(cols[0].get_text()),
                            "modulation": cols[1].get_text().strip(),
                            "snr": extract_float(cols[2].get_text()),
                            "power": extract_float(cols[3].get_text()),
                        }
                    )

            _LOGGER.debug("CGA2121: Parsed %d downstream channels", len(channels))

        except Exception as e:
            _LOGGER.error("Error parsing CGA2121 downstream channels: %s", e)

        return channels

    def _parse_upstream(self, soup: BeautifulSoup) -> list[dict]:
        """Parse upstream channel data from CGA2121."""
        channels: list[dict] = []

        try:
            tbody = self._find_channel_tbody(soup, "Upstream Channels", "ds_link_upstream_channels")
            if not tbody:
                return channels

            for row in tbody.find_all("tr"):
                cols = row.find_all("td")
                if len(cols) >= 3:
                    channels.append(
                        {
                            "channel_id": extract_number(cols[0].get_text()),
                            "modulation": cols[1].get_text().strip(),
                            "power": extract_float(cols[2].get_text()),
                        }
                    )

            _LOGGER.debug("CGA2121: Parsed %d upstream channels", len(channels))

        except Exception as e:
            _LOGGER.error("Error parsing CGA2121 upstream channels: %s", e)

        return channels

    def _parse_system_info(self, soup: BeautifulSoup) -> dict:
        """
        Parse system information from CGA2121.

        The status page has limited system info - mainly operational status.
        """
        info = {}

        try:
            # Try to find operational status
            for row in soup.find_all("tr"):
                header = row.find("th")
                value = row.find("td")
                if header and value:
                    header_text = header.get_text().strip()
                    value_text = value.get_text().strip()

                    if "Operational Status" in header_text:
                        info["operational_status"] = value_text
                    elif "Downstream Channels" in header_text:
                        info["downstream_channel_count"] = extract_number(value_text)
                    elif "Upstream Channels" in header_text:
                        info["upstream_channel_count"] = extract_number(value_text)
                    elif "Baseline Privacy" in header_text:
                        info["baseline_privacy"] = value_text

        except Exception as e:
            _LOGGER.error("Error parsing CGA2121 system info: %s", e)

        return info

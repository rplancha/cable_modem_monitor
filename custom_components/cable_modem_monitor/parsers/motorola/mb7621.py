"""Parser for Motorola MB7621 cable modem.

The Motorola MB7621 is a DOCSIS 3.0 cable modem with 24x8 channel bonding.

Key pages:
- /MotoSwInfo.asp: Software/hardware info (publicly accessible)
- /MotoConnection.asp: Channel data (requires auth)
- /MotoHome.asp: System info (requires auth)
- /MotoSecurity.asp: Security settings / restart

Authentication: Form-based with Base64-encoded password
"""

from __future__ import annotations

import logging

from bs4 import BeautifulSoup

from custom_components.cable_modem_monitor.lib.utils import extract_float, extract_number, parse_uptime_to_seconds

from ..base_parser import ModemCapability, ModemParser, ParserStatus

_LOGGER = logging.getLogger(__name__)

# During modem restart, power readings may be temporarily zero.
# Ignore zero power readings during the first 5 minutes after boot.
RESTART_WINDOW_SECONDS = 300


class MotorolaMB7621Parser(ModemParser):
    """Parser for the Motorola MB7621 cable modem."""

    name = "Motorola MB7621"
    manufacturer = "Motorola"
    models = ["MB7621"]

    # Parser status
    status = ParserStatus.VERIFIED
    verification_source = "kwschulz (maintainer)"

    # Device metadata
    release_date = "2017"
    docsis_version = "3.0"
    fixtures_path = "tests/parsers/motorola/fixtures/mb7621"

    # Form auth hints for AuthDiscovery (v3.12.0+)
    # MB7621 requires Base64-encoded passwords with non-standard field names
    auth_form_hints = {
        "username_field": "loginUsername",
        "password_field": "loginPassword",
        "login_url": "/goform/login",
        "password_encoding": "base64",  # MB7621 requires Base64-encoded passwords
        "success_indicator": "10000",  # Response length > this indicates success
    }

    url_patterns = [
        {"path": "/MotoSwInfo.asp", "auth_method": "form", "auth_required": False},
        {"path": "/MotoConnection.asp", "auth_method": "form", "auth_required": True},
        {"path": "/MotoHome.asp", "auth_method": "form", "auth_required": True},
    ]

    # Capabilities
    capabilities = {
        ModemCapability.DOWNSTREAM_CHANNELS,
        ModemCapability.UPSTREAM_CHANNELS,
        ModemCapability.SYSTEM_UPTIME,
        ModemCapability.SOFTWARE_VERSION,
        ModemCapability.RESTART,
    }

    @classmethod
    def can_parse(cls, soup: BeautifulSoup, url: str, html: str) -> bool:
        """Detect if this is a Motorola MB7621 modem."""
        # Check for MB7621-specific indicators in the HTML
        return "MB7621" in html or "MB 7621" in html or "2480-MB7621" in html

    def parse(self, soup: BeautifulSoup, session=None, base_url=None) -> dict:
        """Parse all data from the modem."""
        system_info = self._parse_system_info(soup)

        # Check if we have the connection page with channel data
        # If not (e.g., we got the public info page or login response), fetch MotoConnection.asp
        # MotoConnection.asp has channel data AND system uptime (but NOT software_version)
        # NOTE: MotoHome.asp also has moto-table-content tables (system info), so we check
        # for channel-specific tables (those with Pwr/SNR headers)
        has_channel_data = self._has_channel_tables(soup)
        if not has_channel_data and session and base_url:
            _LOGGER.debug("No channel tables found, fetching MotoConnection.asp for channel data")
            try:
                conn_response = session.get(f"{base_url}/MotoConnection.asp", timeout=10)
                if conn_response.status_code == 200:
                    soup = BeautifulSoup(conn_response.text, "html.parser")
                    _LOGGER.debug("Fetched MotoConnection.asp (%d bytes)", len(conn_response.text))
                    # MotoConnection.asp contains uptime - update system_info
                    conn_info = self._parse_system_info(soup)
                    system_info.update(conn_info)
                    _LOGGER.debug("Updated system_info from MotoConnection.asp: %s", conn_info)
                else:
                    _LOGGER.warning("Failed to fetch MotoConnection.asp: status %d", conn_response.status_code)
            except Exception as e:
                _LOGGER.error("Failed to fetch MotoConnection.asp: %s", e)

        # Fetch MotoHome.asp if software version is still missing
        # (MotoConnection.asp has uptime but NOT software_version)
        if not system_info.get("software_version") and session and base_url:
            try:
                _LOGGER.debug("Software version not found, fetching MotoHome.asp")
                home_response = session.get(f"{base_url}/MotoHome.asp", timeout=10)
                if home_response.status_code == 200:
                    home_soup = BeautifulSoup(home_response.text, "html.parser")
                    home_info = self._parse_system_info(home_soup)
                    system_info.update(home_info)
                    _LOGGER.debug("Updated system_info from MotoHome.asp: %s", home_info)
            except Exception as e:
                _LOGGER.error("Failed to fetch MotoHome.asp: %s", e)

        downstream_channels = self._parse_downstream(soup, system_info)
        upstream_channels = self._parse_upstream(soup, system_info)

        _LOGGER.debug("Final system_info being returned: %s", system_info)
        return {
            "downstream": downstream_channels,
            "upstream": upstream_channels,
            "system_info": system_info,
        }

    def _has_channel_tables(self, soup: BeautifulSoup) -> bool:
        """Check if the soup contains channel data tables (not just system info tables).

        MotoHome.asp has moto-table-content tables with system info, but no channel data.
        MotoConnection.asp has moto-table-content tables WITH Pwr/SNR headers for channels.
        """
        tables = soup.find_all("table", class_="moto-table-content")
        for table in tables:
            headers = [
                th.text.strip()
                for th in table.find_all(["th", "td"], class_=["moto-param-header-s", "moto-param-header"])
            ]
            if self._is_downstream_table(headers):
                return True
        return False

    def _is_downstream_table(self, headers: list[str]) -> bool:
        """Check if table headers indicate a downstream channel table."""
        return any("Pwr" in h for h in headers) and any("SNR" in h for h in headers)

    def _filter_restart_values(
        self, power: float | None, snr: float | None, is_restarting: bool
    ) -> tuple[float | None, float | None]:
        """Filter out zero values during restart window."""
        if is_restarting:
            if power == 0:
                power = None
            if snr == 0:
                snr = None
        return power, snr

    def _parse_downstream_row(self, cols: list, is_restarting: bool) -> dict | None:
        """Parse a single downstream channel row.

        Table structure:
        Channel | Lock Status | Modulation | Channel ID | Freq (MHz) | Pwr | SNR | Corrected | Uncorrected
        cols[0]   cols[1]       cols[2]      cols[3]      cols[4]      [5]   [6]    [7]         [8]
        """
        if len(cols) < 9:
            return None

        try:
            # Channel ID is in column 3 (not column 0 which is just a row counter)
            channel_id = extract_number(cols[3].text)
            if channel_id is None:
                _LOGGER.debug("Skipping row - could not extract channel_id from: %s", cols[3].text)
                return None

            freq_mhz = extract_float(cols[4].text)
            freq_hz = freq_mhz * 1_000_000 if freq_mhz is not None else None

            power = extract_float(cols[5].text)
            snr = extract_float(cols[6].text)
            _LOGGER.debug("Ch %s: Raw Power=%s, Raw SNR=%s", channel_id, power, snr)

            power, snr = self._filter_restart_values(power, snr, is_restarting)

            channel_data = {
                "channel_id": str(channel_id),
                "frequency": freq_hz,
                "power": power,
                "snr": snr,
                "corrected": extract_number(cols[7].text),
                "uncorrected": extract_number(cols[8].text),
                "modulation": cols[2].text.strip(),
            }
            _LOGGER.debug("Parsed downstream channel: %s", channel_data)
            return channel_data
        except Exception as e:
            _LOGGER.error("Error parsing downstream channel row: %s", e)
            return None

    def _parse_downstream(self, soup: BeautifulSoup, system_info: dict) -> list[dict]:
        """Parse downstream channel data."""
        uptime_seconds = parse_uptime_to_seconds(system_info.get("system_uptime", ""))
        is_restarting = uptime_seconds is not None and uptime_seconds < RESTART_WINDOW_SECONDS
        _LOGGER.debug(
            "Uptime: %s, Seconds: %s, Restarting: %s", system_info.get("system_uptime"), uptime_seconds, is_restarting
        )

        channels = []
        try:
            tables_found = soup.find_all("table", class_="moto-table-content")
            _LOGGER.debug("Found %s tables with class 'moto-table-content'", len(tables_found))

            for table in tables_found:
                headers = [
                    th.text.strip()
                    for th in table.find_all(["th", "td"], class_=["moto-param-header-s", "moto-param-header"])
                ]
                _LOGGER.debug("Table headers found: %s", headers)

                if self._is_downstream_table(headers):
                    rows = table.find_all("tr")[1:]
                    _LOGGER.debug("Found downstream table with %s rows", len(rows))

                    for row in rows:
                        cols = row.find_all("td")
                        channel_data = self._parse_downstream_row(cols, is_restarting)
                        if channel_data:
                            channels.append(channel_data)
                    break
        except Exception as e:
            _LOGGER.error("Error parsing downstream channels: %s", e)

        _LOGGER.debug("Parsed %s downstream channels", len(channels))
        return channels

    def _parse_upstream(self, soup: BeautifulSoup, system_info: dict) -> list[dict]:
        """Parse upstream channel data.

        Table structure:
        Channel | Lock Status | Channel Type | Channel ID | Symb. Rate | Freq (MHz) | Pwr
        cols[0]   cols[1]       cols[2]        cols[3]      cols[4]      cols[5]      cols[6]
        """
        uptime_seconds = parse_uptime_to_seconds(system_info.get("system_uptime", ""))
        is_restarting = uptime_seconds is not None and uptime_seconds < RESTART_WINDOW_SECONDS
        _LOGGER.debug(
            "Uptime: %s, Seconds: %s, Restarting: %s", system_info.get("system_uptime"), uptime_seconds, is_restarting
        )
        channels = []
        try:
            for table in soup.find_all("table", class_="moto-table-content"):
                headers = [
                    th.text.strip()
                    for th in table.find_all(["th", "td"], class_=["moto-param-header-s", "moto-param-header"])
                ]
                if any("Symb. Rate" in h for h in headers):
                    rows = table.find_all("tr")[1:]
                    _LOGGER.debug("Found upstream table with %s rows", len(rows))
                    for row in rows:
                        cols = row.find_all("td")
                        if len(cols) >= 7:
                            try:
                                # Channel ID is in column 3 (not column 0 which is just a row counter)
                                channel_id = extract_number(cols[3].text)
                                if channel_id is None:
                                    _LOGGER.debug("Skipping row - could not extract channel_id from: %s", cols[3].text)
                                    continue

                                lock_status = cols[1].text.strip()
                                if "not locked" in lock_status.lower():
                                    _LOGGER.debug(
                                        "Skipping channel %s - not locked (status: %s)", channel_id, lock_status
                                    )
                                    continue

                                freq_mhz = extract_float(cols[5].text)
                                freq_hz = freq_mhz * 1_000_000 if freq_mhz is not None else None

                                power = extract_float(cols[6].text)
                                _LOGGER.debug("Ch %s: Raw Power=%s", channel_id, power)

                                if is_restarting and power == 0:
                                    power = None

                                channel_data = {
                                    "channel_id": str(channel_id),
                                    "frequency": freq_hz,
                                    "power": power,
                                    "modulation": cols[2].text.strip(),
                                }
                                _LOGGER.debug("Parsed upstream channel: %s", channel_data)
                                channels.append(channel_data)
                            except Exception as e:
                                _LOGGER.error("Error parsing upstream channel row: %s", e)
                                continue
                    break
        except Exception as e:
            _LOGGER.error("Error parsing upstream channels: %s", e)

        _LOGGER.debug("Parsed %s upstream channels", len(channels))
        return channels

    def _parse_system_info(self, soup: BeautifulSoup) -> dict:
        """Parse system information."""
        info = {}
        try:
            sw_version_tag = soup.find("td", text=lambda t: bool(t and "Software Version" in t))
            if sw_version_tag:
                sw_version_value = sw_version_tag.find_next_sibling("td")
                if sw_version_value:
                    info["software_version"] = sw_version_value.text.strip()
            else:
                _LOGGER.debug("Software Version tag not found in HTML")

            uptime_tag = soup.find("td", text=lambda t: bool(t and "System Up Time" in t))
            if uptime_tag:
                uptime_value = uptime_tag.find_next_sibling("td")
                if uptime_value:
                    info["system_uptime"] = uptime_value.text.strip()
                    _LOGGER.debug("Found uptime: %s", info["system_uptime"])
            else:
                _LOGGER.debug("System Up Time tag not found in HTML")
        except Exception as e:
            _LOGGER.error("Error parsing system info: %s", e)

        return info

    def restart(self, session, base_url) -> bool:
        """Restart the modem."""
        try:
            security_url = f"{base_url}/MotoSecurity.asp"
            _LOGGER.debug("Accessing security page: %s", security_url)
            security_response = session.get(security_url, timeout=10)

            if security_response.status_code != 200:
                _LOGGER.error("Failed to access security page: %s", security_response.status_code)
                return False

            restart_url = f"{base_url}/goform/MotoSecurity"
            _LOGGER.info("Sending restart command to %s", restart_url)

            restart_data = {
                "UserId": "",
                "OldPassword": "",
                "NewUserId": "",
                "Password": "",
                "PasswordReEnter": "",
                "MotoSecurityAction": "1",
            }
            response = session.post(restart_url, data=restart_data, timeout=10)
            _LOGGER.debug("Restart response: status=%s, content_length=%s", response.status_code, len(response.text))

            if response.status_code == 200:
                _LOGGER.info("Restart command sent successfully")
                return True
            else:
                _LOGGER.error("Restart failed with status code: %s", response.status_code)
                return False

        except ConnectionResetError:
            _LOGGER.info("Restart command sent successfully (connection reset by rebooting modem)")
            return True
        except Exception as e:
            if "Connection aborted" in str(e) or "Connection reset" in str(e):
                _LOGGER.info("Restart command sent successfully (connection reset by rebooting modem)")
                return True
            _LOGGER.error("Error sending restart command: %s", e)
            return False

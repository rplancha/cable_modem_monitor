"""Parser for Virgin Media Hub 5 using REST API.

The Hub 5 is a DOCSIS 3.1 gateway that exposes a REST API at /rest/v1/
with unauthenticated JSON endpoints for modem status.

Naming: Virgin Media has used both "Super Hub 5" and "Hub 5" in their marketing.
We use "superhub5" in filenames/classes for stability, but display as "Virgin Hub 5"
to match their current branding. The models list includes both variations for detection.

Authentication: None required
Data endpoints:
  - GET /rest/v1/cablemodem/downstream
  - GET /rest/v1/cablemodem/upstream
  - GET /rest/v1/cablemodem/state_

Reference: https://github.com/solentlabs/cable_modem_monitor/issues/82
"""

from __future__ import annotations

import logging
from typing import Any

from bs4 import BeautifulSoup

from ..base_parser import ModemCapability, ModemParser, ParserStatus

_LOGGER = logging.getLogger(__name__)


class VirginSuperHub5Parser(ModemParser):
    """Parser for Virgin Media Hub 5 using REST API.

    OEM: Sagemcom F3896LG-VMB
    Chipset: Broadcom 3390S (per ISPreview)

    Note: User's bootFilename shows "vmdg660" - linkage to F3896LG-VMB inferred.
    """

    name = "Virgin Hub 5"
    manufacturer = "Virgin Media"
    models = ["Hub 5", "SuperHub 5", "VMDG660", "F3896LG-VMB"]
    priority = 100

    # Parser status
    status = ParserStatus.AWAITING_VERIFICATION
    verification_source = "https://github.com/solentlabs/cable_modem_monitor/issues/82"

    # Device metadata
    release_date = "2021"
    docsis_version = "3.1"
    fixtures_path = "tests/parsers/virgin/fixtures/superhub5"

    # No authentication required
    auth_config = None

    url_patterns = [
        {"path": "/rest/v1/cablemodem/state_", "auth_method": "none", "auth_required": False},
        {"path": "/rest/v1/cablemodem/downstream", "auth_method": "none", "auth_required": False},
        {"path": "/rest/v1/cablemodem/upstream", "auth_method": "none", "auth_required": False},
    ]

    # Capabilities
    capabilities = {
        ModemCapability.DOWNSTREAM_CHANNELS,
        ModemCapability.UPSTREAM_CHANNELS,
        ModemCapability.OFDM_DOWNSTREAM,
        ModemCapability.OFDM_UPSTREAM,
        ModemCapability.SYSTEM_UPTIME,
    }

    @classmethod
    def can_parse(cls, soup: BeautifulSoup, url: str, html: str) -> bool:
        """Detect if this is a Virgin SuperHub 5 via REST API response."""
        # The REST API returns JSON, not HTML
        # Check for the cablemodem state structure
        if '"cablemodem"' in html and '"docsisVersion"' in html:
            return True
        # Also check for downstream/upstream JSON structure
        if '"downstream"' in html and '"channels"' in html and '"sc_qam"' in html:
            return True
        return '"upstream"' in html and '"channels"' in html and '"atdma"' in html

    def login(self, session, base_url, username, password) -> tuple[bool, str | None]:
        """No login required - REST API is unauthenticated."""
        return (True, None)

    def parse(self, soup: BeautifulSoup, session=None, base_url=None) -> dict:
        """Parse all data from the SuperHub 5 REST API."""
        downstream_channels: list[dict] = []
        upstream_channels: list[dict] = []
        system_info: dict[str, Any] = {}

        if not session or not base_url:
            _LOGGER.warning("SuperHub 5 parser requires session and base_url")
            return {
                "downstream": downstream_channels,
                "upstream": upstream_channels,
                "system_info": system_info,
            }

        # Fetch and parse state
        system_info = self._fetch_and_parse_state(session, base_url)

        # Fetch and parse downstream channels
        downstream_channels = self._fetch_and_parse_downstream(session, base_url)

        # Fetch and parse upstream channels
        upstream_channels = self._fetch_and_parse_upstream(session, base_url)

        return {
            "downstream": downstream_channels,
            "upstream": upstream_channels,
            "system_info": system_info,
        }

    def _fetch_and_parse_state(self, session, base_url: str) -> dict[str, Any]:
        """Fetch and parse system state from REST API."""
        info: dict[str, Any] = {}

        try:
            response = session.get(f"{base_url}/rest/v1/cablemodem/state_", timeout=30)
            if response.status_code != 200:
                _LOGGER.error("SuperHub 5 state request failed: %s", response.status_code)
                return info

            data = response.json()
            cm = data.get("cablemodem", {})

            # Uptime in seconds
            uptime_seconds = cm.get("upTime")
            if uptime_seconds is not None:
                info["uptime_seconds"] = uptime_seconds
                info["system_uptime"] = self._format_uptime(uptime_seconds)

            # DOCSIS version
            if cm.get("docsisVersion"):
                info["docsis_version"] = cm["docsisVersion"]

            # Status
            if cm.get("status"):
                info["status"] = cm["status"]

            # Model info from boot filename (e.g., "cmreg-vmdg660-bbt076-b.cm")
            boot_file = cm.get("bootFilename", "")
            if "vmdg660" in boot_file.lower():
                info["model_name"] = "VMDG660"
            else:
                info["model_name"] = "SuperHub 5"

        except Exception as e:
            _LOGGER.error("SuperHub 5 state request failed: %s", e)

        return info

    def _fetch_and_parse_downstream(self, session, base_url: str) -> list[dict]:
        """Fetch and parse downstream channels from REST API."""
        channels: list[dict] = []

        try:
            response = session.get(f"{base_url}/rest/v1/cablemodem/downstream", timeout=30)
            if response.status_code != 200:
                _LOGGER.error("SuperHub 5 downstream request failed: %s", response.status_code)
                return channels

            data = response.json()
            raw_channels = data.get("downstream", {}).get("channels", [])

            for ch in raw_channels:
                if not ch.get("lockStatus"):
                    continue

                channel_type = ch.get("channelType", "").lower()
                is_ofdm = channel_type == "ofdm"

                channel: dict[str, Any] = {
                    "channel_id": str(ch.get("channelId", "")),
                    "lock_status": "Locked" if ch.get("lockStatus") else "Not Locked",
                    "modulation": self._normalize_modulation(ch.get("modulation", "")),
                    "frequency": ch.get("frequency", 0),
                    "power": self._parse_float(ch.get("power")),
                    "snr": self._parse_float(ch.get("snr") or ch.get("rxMer")),
                    "corrected": ch.get("correctedErrors", 0),
                    "uncorrected": ch.get("uncorrectedErrors", 0),
                    "is_ofdm": is_ofdm,
                    "channel_type": channel_type,
                }

                # OFDM-specific fields
                if is_ofdm:
                    channel["channel_width"] = ch.get("channelWidth", 0)
                    channel["fft_type"] = ch.get("fftType", "")
                    channel["active_subcarriers"] = ch.get("numberOfActiveSubCarriers", 0)

                channels.append(channel)

        except Exception as e:
            _LOGGER.error("SuperHub 5 downstream request failed: %s", e)

        return channels

    def _fetch_and_parse_upstream(self, session, base_url: str) -> list[dict]:
        """Fetch and parse upstream channels from REST API."""
        channels: list[dict] = []

        try:
            response = session.get(f"{base_url}/rest/v1/cablemodem/upstream", timeout=30)
            if response.status_code != 200:
                _LOGGER.error("SuperHub 5 upstream request failed: %s", response.status_code)
                return channels

            data = response.json()
            raw_channels = data.get("upstream", {}).get("channels", [])

            for ch in raw_channels:
                if not ch.get("lockStatus"):
                    continue

                channel_type = ch.get("channelType", "").lower()
                is_ofdm = channel_type == "ofdma"

                channel: dict[str, Any] = {
                    "channel_id": str(ch.get("channelId", "")),
                    "lock_status": "Locked" if ch.get("lockStatus") else "Not Locked",
                    "modulation": self._normalize_modulation(ch.get("modulation", "")),
                    "frequency": ch.get("frequency", 0),
                    "power": self._parse_float(ch.get("power")),
                    "symbol_rate": ch.get("symbolRate", 0),
                    "is_ofdm": is_ofdm,
                    "channel_type": channel_type,
                }

                # OFDMA-specific fields
                if is_ofdm:
                    channel["channel_width"] = ch.get("channelWidth", 0)
                    channel["fft_type"] = ch.get("fftType", "")
                    channel["active_subcarriers"] = ch.get("numberOfActiveSubCarriers", 0)

                channels.append(channel)

        except Exception as e:
            _LOGGER.error("SuperHub 5 upstream request failed: %s", e)

        return channels

    def _format_uptime(self, seconds: int) -> str:
        """Format uptime seconds to human readable string."""
        days, remainder = divmod(seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, secs = divmod(remainder, 60)

        if days > 0:
            return f"{days}d {hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    def _parse_float(self, value: Any) -> float:
        """Parse float value, handling various input types."""
        if value is None:
            return 0.0
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return 0.0
            try:
                return float(value)
            except ValueError:
                return 0.0
        return 0.0

    def _normalize_modulation(self, mod: str) -> str:
        """Normalize modulation string to standard format."""
        if not mod:
            return ""
        # Convert from API format (e.g., "qam_256") to display format (e.g., "QAM256")
        mod_upper = mod.upper().replace("_", "")
        return mod_upper

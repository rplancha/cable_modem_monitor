"""HNAP/SOAP session-based authentication."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import requests

from ..base import AuthStrategy

if TYPE_CHECKING:
    from ..configs import AuthConfig, HNAPAuthConfig

_LOGGER = logging.getLogger(__name__)


class HNAPSessionAuthStrategy(AuthStrategy):
    """HNAP/SOAP session-based authentication."""

    def login(
        self,
        session: requests.Session,
        base_url: str,
        username: str | None,
        password: str | None,
        config: AuthConfig,
    ) -> tuple[bool, str | None]:
        """Establish HNAP session."""
        if not username or not password:
            _LOGGER.warning(
                "HNAP authentication requires credentials. "
                "Username provided: %s, Password provided: %s. "
                "Please configure username and password in the integration settings.",
                bool(username),
                bool(password),
            )
            return (False, None)

        from ..configs import HNAPAuthConfig

        if not isinstance(config, HNAPAuthConfig):
            _LOGGER.error("HNAPSessionAuthStrategy requires HNAPAuthConfig")
            return (False, None)

        try:
            # Build login SOAP envelope
            login_envelope = self._build_login_envelope(username, password, config)

            hnap_url = f"{base_url}{config.hnap_endpoint}"
            _LOGGER.debug(
                "HNAP login attempt: URL=%s, Username=%s (length=%d), Password length=%d",
                hnap_url,
                username,
                len(username) if username else 0,
                len(password) if password else 0,
            )

            response = session.post(
                hnap_url,
                data=login_envelope,
                headers={
                    "SOAPAction": f'"{config.soap_action_namespace}Login"',
                    "Content-Type": "text/xml; charset=utf-8",
                },
                timeout=10,
                verify=session.verify,
            )

            _LOGGER.debug(
                "HNAP login response: status=%d, response_length=%d bytes, content_type=%s",
                response.status_code,
                len(response.text),
                response.headers.get("Content-Type", "unknown"),
            )

            if response.status_code != 200:
                _LOGGER.error(
                    "HNAP login failed with HTTP status %s. Response preview: %s",
                    response.status_code,
                    response.text[:500] if response.text else "empty",
                )
                return (False, None)

            # Check for session timeout indicator (means auth failed)
            if config.session_timeout_indicator in response.text:
                _LOGGER.warning(
                    "HNAP login failed: Found '%s' in response (authentication rejected). " "Response preview: %s",
                    config.session_timeout_indicator,
                    response.text[:500],
                )
                return (False, None)

            # Check for JSON error responses (some MB8611 firmwares return JSON errors)
            error_indicators = [
                "SET_JSON_FORMAT_ERROR",
                "ERROR",
                '"LoginResult":"FAILED"',
                '"LoginResult": "FAILED"',
            ]
            for error_indicator in error_indicators:
                if error_indicator in response.text:
                    _LOGGER.warning(
                        "HNAP login failed: Found error indicator '%s' in response. "
                        "This may indicate the modem requires JSON-formatted HNAP requests "
                        "instead of XML/SOAP. Response preview: %s",
                        error_indicator,
                        response.text[:500],
                    )
                    return (False, None)

            # Log success indicators
            _LOGGER.info(
                "HNAP login successful! Session established with modem. Response size: %d bytes",
                len(response.text),
            )
            _LOGGER.debug("HNAP login response preview: %s", response.text[:300])
            return (True, response.text)

        except requests.exceptions.Timeout as e:
            _LOGGER.error("HNAP login timeout - modem took too long to respond: %s", str(e))
            return (False, None)
        except requests.exceptions.ConnectionError as e:
            _LOGGER.error("HNAP login connection error - cannot reach modem: %s", str(e))
            return (False, None)
        except Exception as e:
            _LOGGER.error("HNAP login exception: %s", str(e), exc_info=True)
            return (False, None)

    def _build_login_envelope(self, username: str, password: str, config: HNAPAuthConfig) -> str:
        """Build SOAP login envelope for HNAP."""
        envelope = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="{config.soap_action_namespace}">
      <Username>{username}</Username>
      <Password>{password}</Password>
      <Captcha></Captcha>
    </Login>
  </soap:Body>
</soap:Envelope>"""
        _LOGGER.debug(
            "HNAP SOAP envelope built: namespace=%s, envelope_size=%d bytes",
            config.soap_action_namespace,
            len(envelope),
        )
        return envelope

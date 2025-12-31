"""Form-based authentication with fallback from plain to Base64."""

from __future__ import annotations

import base64
import logging
from typing import TYPE_CHECKING

from ..base import AuthStrategy

if TYPE_CHECKING:
    import requests

    from ..configs import AuthConfig

_LOGGER = logging.getLogger(__name__)


class FormPlainAndBase64AuthStrategy(AuthStrategy):
    """Form-based authentication with fallback from plain to Base64."""

    def login(
        self,
        session: requests.Session,
        base_url: str,
        username: str | None,
        password: str | None,
        config: AuthConfig,
    ) -> tuple[bool, str | None]:
        """Try plain password first, then Base64-encoded."""
        if not username or not password:
            _LOGGER.debug("No credentials provided, skipping login")
            return (True, None)

        from ..configs import FormAuthConfig

        if not isinstance(config, FormAuthConfig):
            _LOGGER.error("FormPlainAndBase64AuthStrategy requires FormAuthConfig")
            return (False, None)

        login_url = f"{base_url}{config.login_url}"

        # Try plain password first
        passwords_to_try = [
            password,  # Plain password
            base64.b64encode(password.encode("utf-8")).decode("utf-8"),  # Base64-encoded
        ]

        for attempt, pwd in enumerate(passwords_to_try, 1):
            login_data = {
                config.username_field: username,
                config.password_field: pwd,
            }
            pwd_type = "plain" if attempt == 1 else "Base64-encoded"
            _LOGGER.debug("Attempting login with %s password", pwd_type)

            response = session.post(login_url, data=login_data, timeout=10, allow_redirects=True, verify=session.verify)

            # Check success
            success = False
            if config.success_indicator:
                is_in_url = config.success_indicator in response.url
                is_large_response = config.success_indicator.isdigit() and len(response.text) > int(
                    config.success_indicator
                )
                success = is_in_url or is_large_response
            else:
                success = response.status_code == 200

            if success:
                _LOGGER.debug("Form login successful with %s password", pwd_type)
                return (True, response.text)

        _LOGGER.warning("Form login failed with both plain and Base64 passwords")
        return (False, None)

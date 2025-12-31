"""Form-based authentication with plain text password."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..base import AuthStrategy

if TYPE_CHECKING:
    import requests

    from ..configs import AuthConfig

_LOGGER = logging.getLogger(__name__)


class FormPlainAuthStrategy(AuthStrategy):
    """Form-based authentication with plain text password."""

    def login(
        self,
        session: requests.Session,
        base_url: str,
        username: str | None,
        password: str | None,
        config: AuthConfig,
    ) -> tuple[bool, str | None]:
        """Submit form with plain password."""
        if not username or not password:
            _LOGGER.debug("No credentials provided, skipping login")
            return (True, None)

        from ..configs import FormAuthConfig

        if not isinstance(config, FormAuthConfig):
            _LOGGER.error("FormPlainAuthStrategy requires FormAuthConfig")
            return (False, None)

        login_url = f"{base_url}{config.login_url}"
        login_data = {
            config.username_field: username,
            config.password_field: password,
        }

        _LOGGER.debug("Submitting form login to %s", login_url)
        response = session.post(login_url, data=login_data, timeout=10, allow_redirects=True, verify=session.verify)

        # Check success indicator
        if config.success_indicator:
            is_in_url = config.success_indicator in response.url
            is_large_response = config.success_indicator.isdigit() and len(response.text) > int(
                config.success_indicator
            )
            if is_in_url or is_large_response:
                _LOGGER.debug("Form login successful")
                return (True, response.text)
            else:
                _LOGGER.warning("Form login failed: success indicator not found")
                return (False, None)

        # If no success indicator, assume success if status is 200
        if response.status_code == 200:
            return (True, response.text)

        return (False, None)

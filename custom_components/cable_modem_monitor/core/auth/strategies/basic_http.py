"""HTTP Basic Authentication strategy (RFC 7617)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..base import AuthStrategy

if TYPE_CHECKING:
    import requests

    from ..configs import AuthConfig

_LOGGER = logging.getLogger(__name__)


class BasicHttpAuthStrategy(AuthStrategy):
    """HTTP Basic Authentication strategy (RFC 7617)."""

    def login(
        self,
        session: requests.Session,
        base_url: str,
        username: str | None,
        password: str | None,
        config: AuthConfig,
    ) -> tuple[bool, str | None]:
        """Set up HTTP Basic Auth on the session."""
        if not username or not password:
            _LOGGER.debug("No credentials provided for Basic Auth, skipping")
            return (True, None)

        # Attach auth to session (sent with every request)
        session.auth = (username, password)
        _LOGGER.debug("HTTP Basic Auth configured for session")
        return (True, None)

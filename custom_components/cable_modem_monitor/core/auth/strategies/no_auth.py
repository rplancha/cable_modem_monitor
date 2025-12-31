"""No-auth strategy for modems that don't require authentication."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..base import AuthStrategy

if TYPE_CHECKING:
    import requests

    from ..configs import AuthConfig

_LOGGER = logging.getLogger(__name__)


class NoAuthStrategy(AuthStrategy):
    """Strategy for modems that don't require authentication."""

    def login(
        self,
        session: requests.Session,
        base_url: str,
        username: str | None,
        password: str | None,
        config: AuthConfig,
    ) -> tuple[bool, str | None]:
        """No authentication needed."""
        _LOGGER.debug("No authentication required")
        return (True, None)

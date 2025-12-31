"""Base classes for authentication strategies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import requests

    from .configs import AuthConfig


@dataclass
class AuthResult:
    """Result of an authentication attempt.

    Attributes:
        success: Whether authentication succeeded
        response_html: HTML from authenticated page (if applicable)
        error_message: Human-readable error description (if failed)
        requires_retry: Whether the caller should retry with different credentials
    """

    success: bool
    response_html: str | None = None
    error_message: str | None = None
    requires_retry: bool = False


class AuthStrategy(ABC):
    """Abstract base class for authentication strategies.

    All authentication strategies must implement the login() method.
    The login method modifies the session in-place (e.g., setting cookies,
    auth headers) and returns a tuple of (success, response_html).
    """

    @abstractmethod
    def login(
        self,
        session: requests.Session,
        base_url: str,
        username: str | None,
        password: str | None,
        config: AuthConfig,
    ) -> tuple[bool, str | None]:
        """Authenticate with the modem.

        Args:
            session: requests.Session object (modified in-place)
            base_url: Modem base URL (e.g., "http://192.168.100.1")
            username: Username for authentication
            password: Password for authentication
            config: Authentication configuration object

        Returns:
            Tuple of (success: bool, response_html: str | None)
            - success: True if authentication succeeded
            - response_html: HTML from authenticated page (if applicable)
        """
        raise NotImplementedError

"""Authentication strategy type enumeration."""

from __future__ import annotations

from enum import Enum


class AuthStrategyType(Enum):
    """Enumeration of supported authentication strategies."""

    NO_AUTH = "no_auth"
    """No authentication required."""

    BASIC_HTTP = "basic_http"
    """HTTP Basic Authentication (RFC 7617)."""

    FORM_PLAIN = "form_plain"
    """Form-based auth with plain password."""

    FORM_BASE64 = "form_base64"
    """Form-based auth with base64-encoded password."""

    FORM_PLAIN_AND_BASE64 = "form_plain_and_base64"
    """Form-based auth with fallback."""

    REDIRECT_FORM = "redirect_form"
    """Form-based auth with redirect validation."""

    HNAP_SESSION = "hnap_session"
    """HNAP/SOAP session-based authentication."""

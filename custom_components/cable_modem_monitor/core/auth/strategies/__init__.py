"""Authentication strategy implementations."""

from __future__ import annotations

from .basic_http import BasicHttpAuthStrategy
from .form_base64 import FormBase64AuthStrategy
from .form_fallback import FormPlainAndBase64AuthStrategy
from .form_plain import FormPlainAuthStrategy
from .hnap_session import HNAPSessionAuthStrategy
from .no_auth import NoAuthStrategy
from .redirect_form import RedirectFormAuthStrategy

__all__ = [
    "BasicHttpAuthStrategy",
    "FormBase64AuthStrategy",
    "FormPlainAndBase64AuthStrategy",
    "FormPlainAuthStrategy",
    "HNAPSessionAuthStrategy",
    "NoAuthStrategy",
    "RedirectFormAuthStrategy",
]

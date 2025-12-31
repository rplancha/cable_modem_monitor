"""Authentication module for cable modem monitor.

This module provides pluggable authentication strategies for various modem types.

Usage:
    from custom_components.cable_modem_monitor.core.auth import (
        AuthFactory,
        AuthStrategyType,
        BasicAuthConfig,
    )

    # Get a strategy
    strategy = AuthFactory.get_strategy(AuthStrategyType.BASIC_HTTP)

    # Use a config
    config = BasicAuthConfig()
"""

from __future__ import annotations

# Base classes
from .base import AuthResult, AuthStrategy

# Configuration dataclasses
from .configs import (
    AuthConfig,
    BasicAuthConfig,
    FormAuthConfig,
    HNAPAuthConfig,
    NoAuthConfig,
    RedirectFormAuthConfig,
)

# Factory
from .factory import AuthFactory

# HNAP builders
from .hnap import HNAPJsonRequestBuilder, HNAPRequestBuilder

# Strategy classes (for direct instantiation if needed)
from .strategies import (
    BasicHttpAuthStrategy,
    FormBase64AuthStrategy,
    FormPlainAndBase64AuthStrategy,
    FormPlainAuthStrategy,
    HNAPSessionAuthStrategy,
    NoAuthStrategy,
    RedirectFormAuthStrategy,
)

# Types and enums
from .types import AuthStrategyType

__all__ = [
    # Enums
    "AuthStrategyType",
    # Configs
    "AuthConfig",
    "BasicAuthConfig",
    "FormAuthConfig",
    "HNAPAuthConfig",
    "NoAuthConfig",
    "RedirectFormAuthConfig",
    # Base
    "AuthResult",
    "AuthStrategy",
    # Factory
    "AuthFactory",
    # Strategies
    "BasicHttpAuthStrategy",
    "FormBase64AuthStrategy",
    "FormPlainAndBase64AuthStrategy",
    "FormPlainAuthStrategy",
    "HNAPSessionAuthStrategy",
    "NoAuthStrategy",
    "RedirectFormAuthStrategy",
    # HNAP
    "HNAPJsonRequestBuilder",
    "HNAPRequestBuilder",
]

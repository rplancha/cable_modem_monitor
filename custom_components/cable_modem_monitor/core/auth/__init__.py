"""Authentication module for cable modem monitor.

This module provides pluggable authentication strategies for various modem types,
as well as response-driven auth discovery for automatic strategy detection.

Usage:
    from custom_components.cable_modem_monitor.core.auth import (
        AuthFactory,
        AuthStrategyType,
        BasicAuthConfig,
        AuthDiscovery,
        DiscoveryResult,
    )

    # Discover auth strategy (v3.12.0+)
    discovery = AuthDiscovery()
    result = discovery.discover(session, base_url, data_url, user, password, parser)
    if result.success:
        print(f"Detected: {result.strategy}")

    # Get a strategy by type
    strategy = AuthFactory.get_strategy(AuthStrategyType.BASIC_HTTP)

    # Use a config
    config = BasicAuthConfig()
"""

from __future__ import annotations

from .base import AuthResult, AuthStrategy
from .configs import (
    AuthConfig,
    BasicAuthConfig,
    FormAuthConfig,
    HNAPAuthConfig,
    NoAuthConfig,
    RedirectFormAuthConfig,
    UrlTokenSessionConfig,
)
from .discovery import AuthDiscovery, DiscoveredFormConfig, DiscoveryResult
from .factory import AuthFactory
from .handler import AuthHandler
from .hnap import HNAPJsonRequestBuilder, HNAPRequestBuilder
from .strategies import (
    BasicHttpAuthStrategy,
    FormBase64AuthStrategy,
    FormPlainAndBase64AuthStrategy,
    FormPlainAuthStrategy,
    HNAPSessionAuthStrategy,
    NoAuthStrategy,
    RedirectFormAuthStrategy,
    UrlTokenSessionStrategy,
)
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
    "UrlTokenSessionConfig",
    # Base
    "AuthResult",
    "AuthStrategy",
    # Discovery
    "AuthDiscovery",
    "DiscoveredFormConfig",
    "DiscoveryResult",
    # Handler
    "AuthHandler",
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
    "UrlTokenSessionStrategy",
    # HNAP
    "HNAPJsonRequestBuilder",
    "HNAPRequestBuilder",
]

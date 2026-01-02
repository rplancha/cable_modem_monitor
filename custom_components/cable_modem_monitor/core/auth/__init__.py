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
    UrlTokenSessionConfig,
)

# Discovery (v3.12.0+)
from .discovery import AuthDiscovery, DiscoveredFormConfig, DiscoveryResult

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
    UrlTokenSessionStrategy,
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
    "UrlTokenSessionConfig",
    # Base
    "AuthResult",
    "AuthStrategy",
    # Discovery
    "AuthDiscovery",
    "DiscoveredFormConfig",
    "DiscoveryResult",
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

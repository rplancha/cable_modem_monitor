# Authentication System

This module provides pluggable authentication strategies for cable modem connections.

## Overview

Cable modems use various authentication methods:
- **None** - Status pages accessible without login
- **HTTP Basic** - Browser-style username/password prompt
- **Form-based** - HTML login forms (plain, base64, or fallback encoding)
- **HNAP** - Proprietary Arris/Motorola protocol (JSON or XML)
- **Redirect Form** - Login form that redirects on success

The auth system uses the **Strategy Pattern** to encapsulate each method, allowing parsers to declare their auth requirements without implementing the protocol details.

## Architecture

```
Parser                    Auth Module                    Modem
  │                           │                            │
  │  auth_config = FormAuth   │                            │
  │  ─────────────────────►   │                            │
  │                           │                            │
  │  login(session, ...)      │   POST /login              │
  │  ─────────────────────►   │  ─────────────────────►    │
  │                           │                            │
  │                           │   200 OK + session cookie  │
  │   AuthResult(success)     │  ◄─────────────────────    │
  │  ◄─────────────────────   │                            │
  │                           │                            │
  │  (use session for data)   │                            │
```

## How Parsers Use Auth

### 1. Declare auth config as class attribute

```python
from custom_components.cable_modem_monitor.core.auth import (
    AuthStrategyType,
    FormAuthConfig,
)

class MyModemParser(ModemParser):
    auth_config = FormAuthConfig(
        strategy=AuthStrategyType.FORM_PLAIN,
        login_path="/goform/login",
        username_field="loginUsername",
        password_field="loginPassword",
    )
```

### 2. Implement login method

```python
def login(self, session, base_url, username, password) -> bool:
    """Authenticate with the modem."""
    from custom_components.cable_modem_monitor.core.auth import AuthFactory

    strategy = AuthFactory.get_strategy(self.auth_config.strategy)
    result = strategy.authenticate(
        session=session,
        base_url=base_url,
        username=username,
        password=password,
        config=self.auth_config,
    )
    return result.success
```

## Available Strategies

| Strategy | AuthConfig | Use Case |
|----------|------------|----------|
| `NO_AUTH` | `NoAuthConfig` | Public status pages |
| `BASIC_HTTP` | `BasicAuthConfig` | HTTP 401 challenge |
| `FORM_PLAIN` | `FormAuthConfig` | Plain-text form POST |
| `FORM_BASE64` | `FormAuthConfig` | Base64-encoded password |
| `FORM_PLAIN_AND_BASE64` | `FormAuthConfig` | Try plain, fallback to base64 |
| `REDIRECT_FORM` | `RedirectFormAuthConfig` | Form that redirects on success |
| `HNAP_SESSION` | `HNAPAuthConfig` | Arris/Motorola HNAP protocol |
| `URL_TOKEN_SESSION` | `UrlTokenSessionConfig` | URL-based token with session cookie (SB8200 HTTPS) |

## Auth Flow in Discovery vs Polling

### During Discovery (config_flow)
1. User enters credentials
2. Scraper tries each parser's `can_parse()` on fetched HTML
3. Matching parser's `login()` validates credentials
4. Success → credentials cached in config entry

### During Polling (coordinator updates)
1. Scraper uses cached parser
2. Calls `login()` to establish session
3. Fetches data pages with authenticated session
4. Parser extracts channel data

## Known Gaps

All known authentication patterns have been formalized as strategies. If you encounter a new pattern, follow the "Adding a New Strategy" section below.

## Adding a New Strategy

1. Create `strategies/my_auth.py`:
```python
from ..base import AuthResult, AuthStrategy
from ..types import AuthStrategyType

class MyAuthStrategy(AuthStrategy):
    strategy_type = AuthStrategyType.MY_AUTH

    def authenticate(self, session, base_url, username, password, config) -> AuthResult:
        # Implementation
        return AuthResult(success=True, session=session)
```

2. Add to `strategies/__init__.py`
3. Add enum value to `types.py`
4. Add config class to `configs.py` if needed
5. Register in `factory.py`

## HNAP Protocol

HNAP (Home Network Administration Protocol) is used by Arris and some Motorola modems. Two variants exist:

- **XML-based** (`HNAPRequestBuilder`) - Legacy Arris modems
- **JSON-based** (`HNAPJsonRequestBuilder`) - Used by S33, MB8611

Both handle HMAC-MD5 challenge-response authentication. See `hnap/` subdirectory for implementation details.

## Testing

Auth strategies have dedicated tests in `tests/core/test_authentication.py`. When adding a new strategy, add corresponding test cases covering:
- Successful authentication
- Failed authentication (wrong password)
- Network errors
- Edge cases specific to the protocol

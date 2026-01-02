# Authentication System

## Overview

The Cable Modem Monitor uses **response-driven authentication discovery** to handle
the variety of auth methods used by cable modems. Like a browser, we inspect
the modem's response and react accordingly.

**v3.12.0+ Architecture:** Auth discovery runs BEFORE parser detection during setup.
Parsers no longer handle authentication - they just parse data.

## How It Works

### Discovery Flow (Setup & Reconfigure)

```
                    GET / (base URL, anonymous)
                              │
                              ▼
                    ┌─────────────────┐
                    │ Inspect Response │
                    └────────┬────────┘
                             │
    ┌────────────────────────┼────────────────────────┐
    │            ┌───────────┼───────────┐            │
    ▼            ▼           ▼           ▼            ▼
200 + data   401 + header  200 + form  200 + HNAP  302/meta
    │            │           │           │            │
    ▼            ▼           ▼           ▼            ▼
NO_AUTH     BASIC_HTTP   FORM_PLAIN  HNAP_SESSION  Follow →
    │            │           │           │         re-inspect
    └────────────┴───────────┴───────────┴────────────┘
                             │
                             ▼
                  Store in Config Entry
```

### Polling Flow (Each Update)

```
Read auth_strategy from config entry
              │
              ▼
AuthHandler executes stored strategy (no re-discovery)
              │
              ▼
Fetch data pages with authenticated session
              │
              ▼
Parse with cached parser
```

## Supported Auth Strategies

| Strategy | Detection | How It Works |
|----------|-----------|--------------|
| NO_AUTH | 200 + parseable data | Direct access, no login needed |
| BASIC_HTTP | 401 + WWW-Authenticate | HTTP Basic Auth header |
| FORM_PLAIN | 200 + form with password | Parse form, POST credentials |
| FORM_BASE64 | 200 + form + parser hints | Base64-encoded password in form |
| HNAP_SESSION | SOAPAction.js script | HMAC-MD5 challenge-response |
| URL_TOKEN_SESSION | JS form + parser hints | Base64 token in URL |
| UNKNOWN | Unrecognized pattern | Captured for debugging |

## Key Components

### AuthDiscovery (`discovery.py`)

Inspects modem responses to detect authentication requirements:
- Parses login forms automatically
- Follows redirects and meta refreshes
- Captures unknown patterns for debugging

```python
from custom_components.cable_modem_monitor.core.auth import AuthDiscovery

discovery = AuthDiscovery()
result = discovery.discover(session, base_url, data_url, username, password, parser)

if result.success:
    print(f"Strategy: {result.strategy}")  # e.g., AuthStrategyType.FORM_PLAIN
    print(f"Form config: {result.form_config}")  # Form fields if applicable
```

### AuthHandler (`handler.py`)

Runtime handler that applies stored authentication during polling:

```python
from custom_components.cable_modem_monitor.core.auth import AuthHandler

handler = AuthHandler(
    strategy="form_plain",
    form_config=stored_form_config,
)

success, html = handler.authenticate(session, base_url, username, password)
```

### AuthFactory (`factory.py`)

Creates strategy instances for specific authentication types:

```python
from custom_components.cable_modem_monitor.core.auth import AuthFactory, AuthStrategyType

strategy = AuthFactory.get_strategy(AuthStrategyType.BASIC_HTTP)
result = strategy.authenticate(session, base_url, username, password, config)
```

## HNAP Protocol

HNAP (Home Network Administration Protocol) is used by Arris S33, Motorola MB8611, and similar modems.

```
Client                              Server
   │                                   │
   │  POST /HNAP1/                     │
   │  {Action: "request", Username}    │
   │──────────────────────────────────►│
   │                                   │
   │  {Challenge, Cookie, PublicKey}   │
   │◄──────────────────────────────────│
   │                                   │
   │  Compute:                         │
   │  PrivateKey = HMAC-MD5(           │
   │    PublicKey + Password,          │
   │    Challenge)                     │
   │  LoginPassword = HMAC-MD5(        │
   │    PrivateKey, Challenge)         │
   │                                   │
   │  POST /HNAP1/                     │
   │  Cookie: uid=<Cookie>             │
   │  {Action: "login", LoginPassword} │
   │──────────────────────────────────►│
   │                                   │
   │  {LoginResult: "OK"}              │
   │◄──────────────────────────────────│
   │                                   │
   │  Subsequent requests use Cookie   │
```

**Detection:** Page includes `<script src="**/SOAPAction.js">` or similar.

## Form Authentication

Standard HTML form login with automatic field detection.

```
1. GET login page → Parse <form> element
2. Find username field (type="text", name contains "user")
3. Find password field (type="password")
4. Collect hidden fields (CSRF tokens)
5. POST form data
6. Session cookie set for subsequent requests
```

**Parser Hints:** For non-standard forms, parsers can provide:

```python
class MyParser(ModemParser):
    auth_form_hints = {
        "username_field": "webUserName",
        "password_field": "webPassKey",
    }
```

## URL Token Authentication (SB8200)

JavaScript-based auth that encodes credentials in URL.

```
1. Detect: Form has type="button" instead of type="submit"
2. Check parser for js_auth_hints
3. Build URL: /page.html?login_<base64(user:pass)>
4. Include Authorization: Basic header
5. Session token returned for subsequent requests
```

**Parser Hints:**

```python
class SB8200Parser(ModemParser):
    js_auth_hints = {
        "pattern": "url_token_session",
        "login_prefix": "login_",
    }
```

## Parser Integration (v3.12+)

**Parsers no longer handle authentication.** The `AuthDiscovery` system
automatically detects and handles auth before parser detection runs.

### What Parsers DON'T Do Anymore

- No `auth_config` attribute
- No `login()` method
- No auth strategy selection

### What Parsers CAN Provide (Optional)

For non-standard auth patterns, parsers can provide hints:

```python
class MyModemParser(ModemParser):
    # For non-standard form fields
    auth_form_hints = {
        "username_field": "customUserField",
        "password_field": "customPassField",
    }

    # For JavaScript-based auth (like SB8200)
    js_auth_hints = {
        "pattern": "url_token_session",
        "login_prefix": "login_",
    }
```

Most parsers need neither - auth is auto-detected.

## Diagnostics

Auth information is included in diagnostics export:

```json
{
  "auth_discovery": {
    "status": "success",
    "strategy": "hnap_session",
    "strategy_description": "HNAP/SOAP protocol (Arris S33, Motorola MB8611)",
    "form_config": null,
    "captured_response": null
  }
}
```

For failed discoveries, `captured_response` contains the login page HTML
and headers for debugging:

```json
{
  "auth_discovery": {
    "status": "unknown_pattern",
    "strategy": "unknown",
    "captured_response": {
      "status_code": 200,
      "url": "http://192.168.100.1/login.asp",
      "html_sample": "<html>...(truncated)...</html>",
      "headers": {"Content-Type": "text/html"}
    }
  }
}
```

## Adding Support for New Auth Patterns

1. Capture HAR file from browser during login
2. Identify the auth flow from network requests
3. If it matches existing pattern → should auto-detect
4. If new pattern → implement new strategy in `strategies/`
5. Add detection logic to `AuthDiscovery`
6. Add tests using HAR-based mock server

## Module Structure

```
core/auth/
├── __init__.py          # Public exports
├── base.py              # AuthStrategy base class, AuthResult
├── configs.py           # Auth config dataclasses
├── discovery.py         # AuthDiscovery - response-driven detection
├── factory.py           # AuthFactory - strategy instantiation
├── handler.py           # AuthHandler - runtime auth execution
├── types.py             # AuthStrategyType enum
├── strategies/          # Individual auth strategies
│   ├── basic_http.py
│   ├── form_plain.py
│   ├── form_base64.py
│   ├── hnap_session.py
│   └── url_token.py
└── hnap/                # HNAP protocol builders
    ├── json_builder.py
    └── xml_builder.py
```

## Testing

Auth has dedicated tests in:
- `tests/core/test_auth_discovery.py` - Discovery logic
- `tests/core/test_auth_handler.py` - Runtime handler
- `tests/integration/test_auth_mock_server.py` - Mock server tests
- `tests/integration/test_scraper_auth_integration.py` - Scraper integration

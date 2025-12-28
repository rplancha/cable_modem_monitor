# Integration Tests

Integration tests using real HTTP/HTTPS mock servers to verify SSL handling, authentication, and network behavior.

## Why Mock Servers?

Unit tests with `responses` or `requests-mock` mock at the requests layer, not the socket/SSL layer. They can't verify actual SSL handshake behavior.

Mock servers provide:
- Real SSL context control (cipher selection, certificate handling)
- Automated regression testing in CI/CD
- No dependency on physical modem hardware for SSL/auth tests

## Running Integration Tests

```bash
# Run all integration tests
pytest tests/integration/

# Run with verbose output
pytest tests/integration/ -v

# Run specific test file
pytest tests/integration/test_ssl_legacy.py
```

### Prerequisites

The `cryptography` package is required for SSL certificate generation:

```bash
pip install cryptography
```

This is included in `tests/requirements.txt`.

## Test Coverage

### Phase 1: SSL Variations (v3.12.0)

| File | Purpose |
|------|---------|
| `test_ssl_modern.py` | HTTPS with default ciphers works |
| `test_ssl_legacy.py` | HTTPS with SECLEVEL=0 (legacy firmware) |
| `test_http_only.py` | HTTP modems unaffected by SSL changes |

**What's tested:**
- Modern SSL connections work with default settings
- `LegacySSLAdapter` allows connections to legacy servers
- Legacy adapter doesn't break modern connections (backwards compatible)
- HTTP URLs don't get SSL adapter mounted
- SSL error detection keywords (handshake, sslv3, cipher, alert)

**What requires real hardware:**
- Actual `SSLV3_ALERT_HANDSHAKE_FAILURE` from modem firmware
- The 3 skipped tests ("modern client rejected by legacy server") depend on OpenSSL configuration

### Phase 2: Authentication Strategies (Future)

| File (planned) | Modems | Priority |
|----------------|--------|----------|
| `test_auth_none.py` | SB6141, SB6190 | Low |
| `test_auth_basic.py` | CM600, C3700 | Medium |
| `test_auth_form.py` | MB7621, XB7 | Medium |
| `test_auth_hnap.py` | MB8611, S33 | High |
| `test_auth_compal.py` | CH7465, CH7466, CH8978 | High |

## Skipped Tests

Three tests in `test_ssl_legacy.py` may be skipped:

```
SKIPPED: System OpenSSL negotiates with legacy ciphers; cannot test rejection scenario
```

This is expected. These tests verify "modern client fails against legacy-only server" - but most OpenSSL builds still negotiate with 3DES/legacy ciphers. The tests skip gracefully rather than false-fail.

Real validation of the legacy SSL fix requires testing with actual modem hardware (e.g., Arris SB8200).

## Testing Approach

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Unit Tests (tests/*)                               │
│ - Fast, no network                                          │
│ - Uses `responses` mock                                     │
│ - Tests parsing, data transformation, business logic        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Integration Tests (tests/integration/)             │
│ - Real in-process servers                                   │
│ - Tests SSL/TLS, authentication, network behavior           │
│ - Runs in CI/CD                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: Hardware Validation (manual)                       │
│ - Real modem devices                                        │
│ - Pre-release testing by contributors                       │
│ - Validates firmware-specific behavior                      │
└─────────────────────────────────────────────────────────────┘
```

## Adding New Tests

1. Add fixtures to `conftest.py` if new server types are needed
2. Create test file following naming convention: `test_<category>.py`
3. Use `@pytest.mark.integration` marker for CI filtering (optional)
4. Update this README with new test scope

## Related Documentation

- **Release Plan:** `RAW_DATA/RELEASE_PLAN.md` (SSL implementation details)
- **SSL Adapter:** `custom_components/cable_modem_monitor/core/ssl_adapter.py`

# Parser Architecture Design & Rationale

This document captures the key architectural decisions, design rationale, and lessons learned from building the parser plugin system. It serves as a reference for future maintainers and contributors.

---

## Parser Plugin System Overview

The Cable Modem Monitor uses a **modular parser plugin architecture** that allows adding support for new modem models without modifying core integration code.

### Key Benefits

- **Zero core changes needed** - Just add a new parser file
- **Auto-discovery** - Plugin system finds parsers automatically
- **Parser isolation** - Adding/fixing parsers can't break existing ones
- **User control** - Users can manually override auto-detection
- **Performance caching** - Parser choice is cached after first success

---

## Architectural Decisions

### 1. Auto-Discovery Over Manual Registration

**Decision:** Parsers auto-register on import via plugin discovery system

**Rationale:**
- Zero-configuration - developers can't forget to register their parser
- Maintainers don't need to update a central registry
- New parsers are immediately available to the integration

**Trade-off:**
- Slightly slower import time (negligible in practice)
- All parser modules are loaded even if not used

**Implementation:**
- `parsers/__init__.py` scans manufacturer subdirectories
- Imports all modules and registers `ModemParser` subclasses
- Sorted by manufacturer and priority for predictable ordering

### 2. Parser-Specific Validation

**Decision:** Each parser implements its own `validate_channels()` method

**Rationale:**
- Different modems have different channel constraints
- DOCSIS 3.0 vs 3.1 have different frequency ranges
- Some modems have unusual channel counts or configurations
- Allows per-model customization without affecting others

**Benefit:**
- Flexible validation that adapts to modem capabilities
- Parser developers can fine-tune validation for their specific model

**Example:**
```python
def validate_channels(self, downstream, upstream):
    """Custom validation for this modem model."""
    if not (8 <= len(downstream) <= 32):
        raise ValueError(f"Expected 8-32 downstream channels, got {len(downstream)}")
    # Model-specific validation logic...
```

### 3. Parser Priority System

**Decision:** Parsers have a `priority` attribute (default: 50, higher = tried first)

**Rationale:**
- Model-specific parsers should be tried before generic ones
- Allows controlling detection order when multiple parsers might match
- Prevents generic parsers from incorrectly claiming specific models

**Usage:**
- Generic parsers: priority = 40
- Model-specific parsers: priority = 60
- Highly-specific parsers: priority = 100

**Implementation:**
```python
class MotorolarMB7621Parser(ModemParser):
    priority = 60  # Tried before generic Motorola parser (priority=40)
```

### 4. Parser-Owned URL Patterns

**Decision:** Each parser defines its own `url_patterns` with auth methods

**Rationale:**
- Eliminates hardcoded URLs in the core scraper
- Different modems use different page structures and paths
- Auth methods vary by manufacturer (none/basic/form)
- Parser knows best what URLs it needs

**Structure:**
```python
url_patterns = [
    {"path": "/status.html", "auth_method": "basic"},
    {"path": "/connection.asp", "auth_method": "form"},  # fallback
]
```

### 5. Response-Driven Authentication Discovery (v3.12+)

**Decision:** Authentication is auto-discovered by inspecting modem responses, not declared by parsers.

**Rationale:**
- Parsers focus on parsing only - no auth logic needed
- Auth is discovered once during setup, stored in config entry
- Same modem model at different ISPs may have different auth requirements
- Unknown auth patterns are captured for debugging

**How it works (Setup Flow):**
1. `AuthDiscovery.discover()` fetches modem page anonymously
2. Response is inspected: 200+data → NO_AUTH, 401 → BASIC_HTTP, form → FORM_PLAIN, etc.
3. Strategy and form config (if applicable) stored in config entry
4. Parser detection runs on authenticated HTML

**How it works (Polling Flow):**
1. `AuthHandler` reads stored strategy from config entry
2. Executes strategy to authenticate session
3. Scraper fetches data with authenticated session
4. Parser parses the data (no auth involvement)

**Available strategies:** `NO_AUTH`, `BASIC_HTTP`, `FORM_PLAIN`, `FORM_BASE64`, `HNAP_SESSION`, `URL_TOKEN_SESSION`.

**Parser Auth Hints (Optional):**
For non-standard forms, parsers can provide optional hints:
```python
class MyParser(ModemParser):
    auth_form_hints = {"username_field": "webUserName"}  # Non-standard field names
    js_auth_hints = {"pattern": "url_token_session"}     # JS-based auth (SB8200)
```

→ **For implementation details, see [`core/auth/README.md`](../../custom_components/cable_modem_monitor/core/auth/README.md)**

### 6. Three-Tier Parser Selection Strategy

**Decision:** Tiered fallback system for parser selection

**Strategy:**
1. **Tier 1: User explicit selection** (strict, no fallback)
   - User manually selected a parser in config
   - If parsing fails, raise error (don't silently fallback)
   - Respects user's intentional choice

2. **Tier 2: Cached parser from previous detection**
   - Parser that worked last time is tried first
   - Improves performance (skip detection on every poll)
   - Falls back to Tier 3 if cached parser fails

3. **Tier 3: Auto-detection across all parsers**
   - Try each parser's `can_parse()` method
   - First parser that returns True is used
   - Cache the successful parser for next time

**Rationale:**
- User control when needed (ISP-customized firmware)
- Performance optimization via caching
- Automatic detection for ease of setup

### 7. Manufacturer Subdirectories

**Decision:** Organize parsers in manufacturer-specific subdirectories

**Structure:**
```
parsers/
├── arris/
│   └── sb6141.py
├── motorola/
│   ├── generic.py
│   └── mb7621.py
└── technicolor/
    ├── tc4400.py
    └── xb7.py
```

**Rationale:**
- Better organization as parser count grows
- Clear ownership and responsibility
- Easier to find and maintain related parsers
- Allows manufacturer-specific utilities in `__init__.py`

---

## Lessons Learned

### What Worked Well

1. **Auto-discovery system worked perfectly first try**
   - Plugin pattern is well-understood in Python
   - No manual registration headaches
   - Easy to test with simple imports

2. **All existing tests passed without modification**
   - Clean abstraction with base class
   - Backward compatibility maintained
   - Refactoring was safe and non-breaking

3. **Parser isolation prevents interference**
   - Each parser is completely independent
   - Bugs in one parser don't affect others
   - Safe for community contributions

4. **Clear separation of concerns**
   - Scraper handles HTTP/session management
   - Parser handles HTML parsing only
   - Validation is parser-specific

### Areas for Improvement

See **[TECH_DEBT.md](./TECH_DEBT.md)** for tracked improvement items, including:
- Parser-specific unit test coverage (Item #8)
- Error handling standardization (Item #9)
- Detection collision handling (related to Item #4)

---

## Technical Implementation Notes

### BeautifulSoup Import Placement

**Note:** BeautifulSoup is imported in `parsers/__init__.py`

**Why it's fine:**
- BeautifulSoup is already a required dependency
- Import cost is negligible
- All parsers need it anyway

### Parser Detection Order

**Note:** Detection order is deterministic (manufacturer + priority)

**Why it matters:**
- Predictable behavior for debugging
- Higher priority parsers tried first within manufacturer
- Prevents random behavior from dictionary ordering

### Validation Method Override

**Note:** `validate_channels()` can be overridden per-parser

**Usage:**
```python
def validate_channels(self, downstream, upstream):
    """Custom validation for this specific modem."""
    # Override base class validation if needed
    # or call super().validate_channels() and add checks
```

### System Info Merging

**Note:** System info uses dictionary unpacking for clean merging

**Pattern:**
```python
return {
    "downstream": downstream,
    "upstream": upstream,
    **system_info,  # Merge system info at top level
}
```

**Why:** Allows parsers to add arbitrary system fields without modifying core code

### Detection Markers

**Best Practice:** Use unique, stable HTML markers for detection

**Good markers:**
- Model name in page title
- Unique CSS classes or IDs
- Specific table headers
- Software version format

**Bad markers:**
- Generic text that might appear on other modems
- Firmware-version-specific strings
- ISP-customized branding

---

## Future Considerations

### Potential Enhancements

1. **Parser capability flags**
   - Some parsers support restart, others don't
   - Some provide uptime, others don't
   - Could use feature flags to communicate capabilities

2. **Multi-page parsing**
   - Some modems spread data across multiple pages
   - Parser could define multiple URL patterns with roles
   - Scraper would fetch all and pass to parser

3. **Firmware version detection**
   - Track firmware version in device info
   - Warn users when firmware is outdated
   - Help with troubleshooting parser issues

4. **Parser testing framework**
   - Standardized test harness for parsers
   - Common validation tests all parsers should pass
   - Performance benchmarking for parsing speed

5. **Dynamic parser updates**
   - Allow users to install parsers via HACS
   - Separate parser releases from integration releases
   - Community-maintained parser repository

6. **Three-part decomposition (post-30 modems milestone)**
   - **HA Integration (thin)**: config_flow, sensors, device registry - HA-specific wrapper
   - **Standalone Core (stable)**: scraper, parsing strategies, data models - HA-independent, PyPI-extractable
   - **Community Configs (high velocity)**: JSON parser configs + fixtures replace Python parsers

   Key shift: parsers become declarative JSON, not Python code. Core provides parsing *strategies* (HTML table extraction, HNAP, REST), community provides *configuration* per modem.

   Enables:
   - Non-developer contributors can produce complete submissions
   - AI skill guides fixture → JSON config → test validation
   - Maintainer review becomes: schema valid? tests pass? → merge
   - Platform portability (same JSON configs for Python core and browser extension)

   See: `personal/JOURNAL.md` → "2025-12-30: Three-Part Decomposition"

---

## Contributing New Parsers

When creating a new parser, consider:

### Detection Method (`can_parse`)

- Use **unique, stable markers** that won't change with firmware updates
- Check multiple markers if possible (belt-and-suspenders)
- Return False quickly if clearly not this modem
- Avoid expensive parsing in detection

### URL Patterns

- List URLs in **preferred order** (best/most reliable first)
- Include fallback URLs if the modem has multiple pages
- Specify correct auth method for each URL
- Document any special URL handling needed

### Error Handling

- Gracefully handle missing tables/fields
- Return empty lists rather than raising errors when possible
- Log warnings for unexpected HTML structure
- Consider firmware variations in your error handling

### Validation

- Implement `validate_channels()` for model-specific constraints
- Validate data types and ranges
- Provide helpful error messages for debugging
- Consider if validation should be strict or permissive

### Testing

- Provide real HTML fixture (sanitized)
- Test detection with fixture from your modem
- Test detection returns False for other modems' HTML
- Verify all expected fields are parsed
- Test edge cases (missing data, partial tables, etc.)

---

## References

- **Parser Base Class:** `custom_components/cable_modem_monitor/parsers/base_parser.py`
- **Auto-Discovery Code:** `custom_components/cable_modem_monitor/parsers/__init__.py`
- **Parser Template:** `custom_components/cable_modem_monitor/parsers/parser_template.py`
- **Contributing Guide:** `CONTRIBUTING.md`

---

**Document Version:** 1.1
**Last Updated:** December 2025
**Maintainer:** Ken Schulz (@kwschulz)

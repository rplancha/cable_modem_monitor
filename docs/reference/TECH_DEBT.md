# Technical Debt & Improvement Areas

This document tracks known technical debt, architectural issues, and improvement opportunities in the Cable Modem Monitor integration. Items are prioritized by impact and effort.

**Last Updated:** December 2025
**Maintainer:** Ken Schulz (@kwschulz)

---

## Priority Levels

| Priority | Description |
|----------|-------------|
| **P0 - Critical** | Blocking issues, data loss risk, or security concerns |
| **P1 - High** | Maintainability issues that will cause problems as codebase grows |
| **P2 - Medium** | Code quality issues that should be addressed opportunistically |
| **P3 - Low** | Minor improvements, nice-to-haves |

---

## P1 - High Priority

### 1. `__init__.py` Monolith (864 lines)

**Problem:** The main integration file handles too many responsibilities:
- Async setup and teardown
- Service registration (dashboard generation, history clearing)
- Coordinator creation and management
- Channel normalization logic
- Entity migration

**Impact:**
- Difficult to test individual components
- Hard to understand data flow
- Changes risk unintended side effects
- `__init__.py` coverage at 34.77% reflects this complexity

**Remediation:**
1. Extract `services.py` - Dashboard generation and history clearing services
2. Extract `coordinator.py` - DataUpdateCoordinator subclass and update logic
3. Extract `channel_utils.py` - Channel normalization and lookup helpers
4. Keep `__init__.py` as thin orchestration layer

**Effort:** Medium (2-3 focused sessions)

**Files:**
- `custom_components/cable_modem_monitor/__init__.py`

---

### 2. Parser Selection Logic Duplication

**Problem:** Parser selection exists in two places with subtle differences:
- `_select_parser()` in `__init__.py` (runtime selection)
- `_select_parser_for_validation()` in `config_flow.py` (setup-time validation)

**Impact:**
- Risk of behavior divergence between setup and runtime
- Bug fixes may not be applied to both locations
- Harder to reason about parser selection behavior

**Remediation:**
1. Create shared `parser_selection.py` module
2. Single `select_parser()` function with mode parameter or shared core logic
3. Both call sites use the shared implementation

**Effort:** Low (1 session)

**Files:**
- `custom_components/cable_modem_monitor/__init__.py:_select_parser()`
- `custom_components/cable_modem_monitor/config_flow.py:_select_parser_for_validation()`

---

### 3. Config Flow Test Coverage Gap (37%)

**Problem:** The configuration UI flow has low test coverage. Edge cases in modem detection, auth handling, and error paths may have untested bugs.

**Impact:**
- Setup failures may not be caught before release
- User-facing errors may be unclear or incorrect
- Regressions can slip through

**Specific Gaps:**
- ICMP detection during setup
- Legacy SSL cipher detection and user prompts
- Error recovery paths (auth failures, connection timeouts)
- Multi-step form navigation

**Remediation:**
1. Add pytest fixtures for common config flow scenarios
2. Mock aiohttp and HA config entry machinery
3. Test each step transition and error path
4. Target 70%+ coverage

**Effort:** Medium-High (3-4 sessions)

**Files:**
- `custom_components/cable_modem_monitor/config_flow.py`
- `tests/test_config_flow.py`

---

## P2 - Medium Priority

### 4. HNAP/SOAP Builder Complexity

**Problem:** Two separate HNAP builder classes exist:
- `HNAPBuilder` (XML-based, used by SB8200)
- `HNAPJsonBuilder` (JSON-based, used by S33, MB8611)

Both handle similar authentication flows but with different action prefixes and response formats.

**Impact:**
- Potential for divergence in auth logic
- Harder to add new HNAP modems
- Knowledge siloed in implementation details

**Remediation:**
1. Document the HNAP protocol variations in ARCHITECTURE.md
2. Consider base class with shared auth logic, subclasses for XML vs JSON
3. Add integration tests for both builder types

**Effort:** Medium (2 sessions for refactor, 1 for docs)

**Files:**
- `custom_components/cable_modem_monitor/core/hnap_builder.py`
- `custom_components/cable_modem_monitor/core/hnap_json_builder.py`

---

### 5. Channel Lookup Optimization Incomplete

**Problem:** Coordinator creates `_downstream_by_id` and `_upstream_by_id` lookup dictionaries, but sensors still iterate through full channel lists in some cases.

**Impact:**
- O(n) lookups instead of O(1) for modems with many channels
- Performance degrades with 32+ downstream channels
- Inconsistent access patterns

**Remediation:**
1. Audit all sensor value access paths
2. Ensure all lookups use the pre-built dictionaries
3. Add performance test with high channel count fixture

**Effort:** Low (1 session)

**Files:**
- `custom_components/cable_modem_monitor/sensor.py`
- `custom_components/cable_modem_monitor/__init__.py` (coordinator)

---

### 6. Sensor Value Access Lacks Validation

**Problem:** Sensors directly access coordinator data without checking if expected keys/channels exist. Missing data can result in silent `None` values or AttributeError.

**Impact:**
- Hard to debug missing sensor values
- Users see "unavailable" without context
- Parser bugs surface as sensor failures

**Remediation:**
1. Add validation layer between coordinator and sensors
2. Log warnings when expected data is missing
3. Expose parsing issues in diagnostics

**Effort:** Low-Medium (1-2 sessions)

**Files:**
- `custom_components/cable_modem_monitor/sensor.py`

---

### 7. Entity Migration Edge Cases

**Problem:** Entity migration (lines 805-807 in `__init__.py`) falls back to parser's `docsis_version` attribute if not in config entry. This assumes the parser instance exists and has the attribute.

**Impact:**
- Migration could fail silently if parser isn't instantiated
- Edge case during upgrades from older versions

**Remediation:**
1. Add explicit check for parser instance
2. Provide sensible default if parser unavailable
3. Log migration decisions for debugging

**Effort:** Low (< 1 session)

**Files:**
- `custom_components/cable_modem_monitor/__init__.py:805-807`

---

### 8. Parser-Specific Unit Test Coverage

**Problem:** Tests currently focus on integration-level testing (full parse with fixtures). Individual parser methods lack isolated unit tests.

**Impact:**
- Harder to pinpoint failures to specific parsing logic
- Edge cases in individual methods may be untested
- Refactoring parsers is riskier without granular tests

**Remediation:**
1. Add unit tests for `can_parse()` detection logic per parser
2. Test individual parsing methods (downstream, upstream, system info) in isolation
3. Create negative tests (malformed HTML, missing tables)
4. Consider pytest parameterization for similar parser families

**Effort:** Medium (ongoing, 1 session per parser family)

**Files:**
- `tests/parsers/` (add per-parser unit test files)

---

### 9. Parser Error Handling Standardization

**Problem:** Parsers handle errors inconsistently. Some return empty lists, some raise exceptions, some log warnings. No common error types or patterns.

**Impact:**
- Inconsistent user experience across modems
- Debugging parser issues requires understanding each parser's approach
- Error messages vary in quality and detail

**Remediation:**
1. Define common exception types in `parsers/exceptions.py`
2. Document expected behavior for missing data vs malformed data
3. Standardize logging patterns across parsers
4. Add parser error summary to diagnostics

**Effort:** Medium (2 sessions)

**Files:**
- `custom_components/cable_modem_monitor/parsers/base_parser.py`
- All parser implementations

---

## P3 - Low Priority

### 10. Test Socket Patching Complexity

**Problem:** Multiple hook levels in conftest.py (pytest_configure, pytest_runtest_setup, pytest_fixture_setup) repeatedly patch and restore socket.socket. Comments indicate this is a workaround for pytest-socket/Home Assistant conflicts.

**Impact:**
- Fragile test setup
- New contributors may break it unknowingly
- Adds cognitive overhead

**Remediation:**
1. Document why the patching is necessary
2. Investigate if newer pytest-socket versions fix the issue
3. Consider pytest plugin isolation

**Effort:** Low (research) to Medium (fix)

**Files:**
- `tests/conftest.py`

---

### 11. Parser Template in Production Code

**Problem:** `parser_template.py` contains TODO comments and placeholder code. It's meant as a starting point for contributors but is visible in the production codebase.

**Impact:**
- Could confuse contributors about what's production code
- Shows up in searches and IDE navigation

**Remediation:**
1. Move to `docs/examples/` or `contrib/`
2. Or add clear header comment explaining it's a template

**Effort:** Trivial

**Files:**
- `custom_components/cable_modem_monitor/parsers/parser_template.py`

---

### 12. Type Safety Relaxation

**Problem:** Mypy is configured with `disallow_untyped_defs = False` and tests/tools are excluded from type checking.

**Impact:**
- Type errors in critical paths may be missed
- Reduces confidence in refactoring

**Remediation:**
1. Incrementally enable stricter settings
2. Add type stubs for HA components where missing
3. Run mypy on tests (after fixing violations)

**Effort:** Medium-High (ongoing)

**Files:**
- `pyproject.toml` (mypy config)

---

### 13. Database Query String Formatting

**Problem:** Lines 666-677 and 705-722 use `# nosec B608` to suppress Bandit SQL injection warnings. The queries are actually safe (using `?` placeholders), but the suppression comments could be clearer.

**Impact:**
- Security reviewers may flag these
- Comments don't explain why it's safe

**Remediation:**
1. Add inline comments explaining the parameterization
2. Or refactor to make the safety more obvious

**Effort:** Trivial

**Files:**
- `custom_components/cable_modem_monitor/__init__.py:666-677, 705-722`

---

### 14. `__init__.py` File Inconsistency Across Packages

**Problem:** Package `__init__.py` files have inconsistent structure:
- Parser manufacturer dirs (arris, motorola, etc.) have docstring + `from __future__ import annotations`
- Some dirs have only a docstring (tests/core, tests/lib, scripts/utils)
- Some are completely empty (custom_components/, tests/, tests/utils/)

**Impact:**
- Inconsistent codebase appearance
- Missing `from __future__ import annotations` may cause issues if type hints are added later
- No clear standard for contributors to follow

**Remediation:**
1. Define standard: docstring + `from __future__ import annotations` for all `__init__.py`
2. Update empty files with minimal docstring describing the package
3. Add `from __future__` to files that have docstrings but lack it

**Effort:** Trivial

**Files:**
- `custom_components/__init__.py` (empty)
- `custom_components/cable_modem_monitor/utils/__init__.py` (empty)
- `scripts/utils/__init__.py` (missing `from __future__`)
- `tests/__init__.py` (empty)
- `tests/components/__init__.py` (empty)
- `tests/utils/__init__.py` (empty)
- `tests/core/__init__.py` (missing `from __future__`)
- `tests/lib/__init__.py` (missing `from __future__`)
- `tests/integration/__init__.py` (missing `from __future__`)
- `tests/parsers/universal/__init__.py` (missing `from __future__`)
- `tests/parsers/virgin/__init__.py` (missing `from __future__`)

---

## Related Documentation

For feature roadmap and architectural enhancements (not code debt), see:
- **[ARCHITECTURE.md](./ARCHITECTURE.md)** → "Future Considerations" section

Items consolidated from ARCHITECTURE.md "What Could Be Improved":
- Parser-specific unit tests → Item #8 above
- Error handling standardization → Item #9 above
- Detection collision handling → Related to Item #4 (HNAP complexity)

---

## Completed Items

_Move items here when resolved, with date and PR reference._

---

## Notes

### Adding New Items

When adding technical debt items:
1. Assign a priority (P0-P3)
2. Describe the problem and impact clearly
3. Suggest remediation approach
4. Estimate effort (Trivial/Low/Medium/High)
5. List affected files

### Addressing Items

When working on an item:
1. Create a branch: `refactor/tech-debt-<item-number>`
2. Reference this document in the PR description
3. Update tests as needed
4. Move to Completed section when merged

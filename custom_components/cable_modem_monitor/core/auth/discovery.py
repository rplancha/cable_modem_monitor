"""Response-driven authentication discovery.

This module implements browser-like auth discovery by inspecting HTTP responses
and reacting accordingly. Instead of trial-and-error with predefined strategies,
we let the modem tell us what authentication it needs.

Usage:
    from custom_components.cable_modem_monitor.core.auth.discovery import (
        AuthDiscovery,
        DiscoveryResult,
        DiscoveredFormConfig,
    )

    discovery = AuthDiscovery()
    result = discovery.discover(
        session=session,
        base_url="http://192.168.100.1",
        data_url="http://192.168.100.1/status.html",
        username="admin",
        password="password",
        parser=my_parser,
    )

    if result.success:
        print(f"Detected: {result.strategy}")
    else:
        print(f"Failed: {result.error_message}")
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .types import AuthStrategyType

if TYPE_CHECKING:
    import requests

    from custom_components.cable_modem_monitor.parsers.base_parser import ModemParser

_LOGGER = logging.getLogger(__name__)


@dataclass
class DiscoveredFormConfig:
    """Form configuration discovered from login page HTML.

    This captures everything needed to submit a login form:
    - action: Where to submit the form
    - method: POST or GET
    - username_field: Input name for username
    - password_field: Input name for password
    - hidden_fields: CSRF tokens and other hidden inputs
    """

    action: str
    method: str
    username_field: str
    password_field: str
    hidden_fields: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize for config entry storage."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> DiscoveredFormConfig:
        """Deserialize from config entry."""
        return cls(**data)


@dataclass
class DiscoveryResult:
    """Result of auth discovery.

    Attributes:
        success: Whether discovery completed and auth strategy was determined
        strategy: The detected AuthStrategyType (may be UNKNOWN if unrecognized)
        form_config: Discovered form configuration (if form-based auth)
        response_html: HTML from authenticated page (for parser detection)
        error_message: Human-readable error (if failed)
        captured_response: Debug info for unknown patterns (for diagnostics)
    """

    success: bool
    strategy: AuthStrategyType | None = None
    form_config: DiscoveredFormConfig | None = None
    response_html: str | None = None
    error_message: str | None = None
    captured_response: dict | None = None


class AuthDiscovery:
    """Discovers authentication requirements by inspecting HTTP responses.

    This class implements browser-like behavior:
    1. Fetch the target URL anonymously
    2. Inspect the response (status code, headers, content)
    3. React appropriately (follow redirects, submit forms, etc.)
    4. Return the discovered strategy and any captured configuration

    Supported patterns:
    - 200 + parseable data → NO_AUTH
    - 401 + WWW-Authenticate → BASIC_HTTP
    - 200 + login form → FORM_PLAIN (with form introspection)
    - 200 + HNAP scripts → HNAP_SESSION
    - 302 or meta refresh → Follow redirect, re-inspect
    - Unrecognized → UNKNOWN (captured for debugging)
    """

    # Generic hints for form field detection
    USERNAME_HINTS = ["user", "login", "name", "account", "id"]
    PASSWORD_HINTS = ["pass", "pwd", "secret", "key"]

    # HNAP detection patterns
    HNAP_SCRIPT_PATTERNS = ["soapaction", "hnap"]

    def discover(
        self,
        session: requests.Session,
        base_url: str,
        data_url: str,
        username: str | None,
        password: str | None,
        parser: ModemParser | None = None,
    ) -> DiscoveryResult:
        """Discover auth requirements by inspecting the response.

        Args:
            session: requests.Session (will be modified with auth)
            base_url: Modem base URL (e.g., "http://192.168.100.1")
            data_url: URL to fetch data from
            username: Credentials (may be None)
            password: Credentials (may be None)
            parser: Parser instance (for validation and hints). May be None for
                discovery-only mode during initial setup (before parser detection).

        Returns:
            DiscoveryResult with strategy and any discovered config
        """
        _LOGGER.debug(
            "Starting auth discovery for %s (parser: %s)",
            data_url,
            parser.name if parser else "None (discovery-only mode)",
        )

        # Step 1: Fetch anonymously (don't follow redirects)
        try:
            response = session.get(data_url, timeout=10, allow_redirects=False)
        except Exception as e:
            _LOGGER.debug("Connection failed during discovery: %s", e)
            return self._error_result(f"Connection failed: {e}")

        # Step 2: Inspect and react
        return self._handle_response(
            response=response,
            session=session,
            base_url=base_url,
            data_url=data_url,
            username=username,
            password=password,
            parser=parser,
            redirect_count=0,
        )

    def _handle_response(
        self,
        response: requests.Response,
        session: requests.Session,
        base_url: str,
        data_url: str,
        username: str | None,
        password: str | None,
        parser: ModemParser | None,
        redirect_count: int,
    ) -> DiscoveryResult:
        """Route to appropriate handler based on response."""
        # Prevent infinite redirect loops
        if redirect_count > 5:
            return self._error_result("Too many redirects during auth discovery.")

        _LOGGER.debug(
            "Handling response: status=%d, url=%s",
            response.status_code,
            response.url,
        )

        # Case 1: 401 Unauthorized - Basic HTTP Auth
        if response.status_code == 401:
            return self._handle_basic_auth(
                session=session,
                data_url=data_url,
                username=username,
                password=password,
                parser=parser,
            )

        # Case 2: Redirect (302, 303, 307, or meta refresh)
        if self._is_redirect(response):
            redirect_url = self._get_redirect_url(response, base_url)
            return self._handle_redirect(
                session=session,
                base_url=base_url,
                redirect_url=redirect_url,
                data_url=data_url,
                username=username,
                password=password,
                parser=parser,
                redirect_count=redirect_count + 1,
            )

        # Case 3: 200 OK - Check content
        if response.status_code == 200:
            # Is it an HNAP modem? (check before form - HNAP pages may have forms)
            if self._is_hnap_page(response.text):
                return self._handle_hnap_auth(
                    session=session,
                    base_url=base_url,
                    data_url=data_url,
                    username=username,
                    password=password,
                    parser=parser,
                )

            # Is it a login form?
            if self._is_login_form(response.text):
                # Check for JavaScript-based auth (button instead of submit)
                if self._is_js_form(response.text):
                    return self._handle_js_auth(
                        session=session,
                        base_url=base_url,
                        form_html=response.text,
                        data_url=data_url,
                        username=username,
                        password=password,
                        parser=parser,
                    )

                return self._handle_form_auth(
                    session=session,
                    base_url=base_url,
                    form_html=response.text,
                    data_url=data_url,
                    username=username,
                    password=password,
                    parser=parser,
                )

            # Is it parseable data? (no auth required)
            if self._can_parse_data(response.text, parser):
                _LOGGER.debug("No auth required - data parseable directly")
                return DiscoveryResult(
                    success=True,
                    strategy=AuthStrategyType.NO_AUTH,
                    form_config=None,
                    response_html=response.text,
                    error_message=None,
                    captured_response=None,
                )

        # Unknown pattern - capture for debugging
        _LOGGER.debug(
            "Unknown auth pattern: status=%d, has_form=%s",
            response.status_code,
            self._is_login_form(response.text) if response.text else False,
        )
        return self._unknown_result(response)

    def _handle_basic_auth(
        self,
        session: requests.Session,
        data_url: str,
        username: str | None,
        password: str | None,
        parser: ModemParser | None,
    ) -> DiscoveryResult:
        """Handle 401 Basic Auth challenge."""
        if not username or not password:
            return self._error_result("Authentication required (HTTP 401). Please provide credentials.")

        # Retry with Basic Auth
        session.auth = (username, password)
        try:
            response = session.get(data_url, timeout=10)
            if response.status_code == 200:
                if self._can_parse_data(response.text, parser):
                    _LOGGER.debug("Basic HTTP auth succeeded")
                    return DiscoveryResult(
                        success=True,
                        strategy=AuthStrategyType.BASIC_HTTP,
                        form_config=None,
                        response_html=response.text,
                        error_message=None,
                        captured_response=None,
                    )
            elif response.status_code == 401:
                return self._error_result("Invalid credentials (HTTP 401).")
        except Exception as e:
            return self._error_result(f"Basic auth failed: {e}")

        return self._unknown_result(response)

    def _handle_form_auth(
        self,
        session: requests.Session,
        base_url: str,
        form_html: str,
        data_url: str,
        username: str | None,
        password: str | None,
        parser: ModemParser | None,
    ) -> DiscoveryResult:
        """Handle form-based authentication."""
        if not username or not password:
            return self._error_result("Login form detected. Please provide credentials.")

        # Parse the form
        form_config = self._parse_login_form(form_html, parser)
        if not form_config:
            return self._error_result("Login form detected but could not parse form fields.")

        _LOGGER.debug(
            "Parsed form: action=%s, method=%s, user_field=%s, pass_field=%s, hidden=%s",
            form_config.action,
            form_config.method,
            form_config.username_field,
            form_config.password_field,
            list(form_config.hidden_fields.keys()),
        )

        # Build form data
        form_data = {
            form_config.username_field: username,
            form_config.password_field: password,
            **form_config.hidden_fields,
        }

        # Submit form
        action_url = self._resolve_url(base_url, form_config.action)
        try:
            if form_config.method.upper() == "POST":
                response = session.post(action_url, data=form_data, timeout=10)
            else:
                response = session.get(action_url, params=form_data, timeout=10)
        except Exception as e:
            return self._error_result(f"Form submission failed: {e}")

        # Check for success - fetch data page
        try:
            data_response = session.get(data_url, timeout=10)

            # First check if we're still on login page (credentials rejected)
            # This is important when parser=None (discovery-only mode)
            if self._is_login_form(data_response.text):
                _LOGGER.debug("Data page still shows login form - credentials rejected")
                return self._error_result("Invalid credentials. Still on login page after form submission.")

            if self._can_parse_data(data_response.text, parser):
                _LOGGER.debug("Form auth succeeded")
                return DiscoveryResult(
                    success=True,
                    strategy=AuthStrategyType.FORM_PLAIN,
                    form_config=form_config,
                    response_html=data_response.text,
                    error_message=None,
                    captured_response=None,
                )
        except Exception as e:
            _LOGGER.debug("Post-auth data fetch failed: %s", e)

        # Check if we're still on login page (wrong credentials)
        if self._is_login_form(response.text):
            return self._error_result("Invalid credentials. Login form returned.")

        return self._unknown_result(response)

    def _handle_hnap_auth(
        self,
        session: requests.Session,
        base_url: str,
        data_url: str,
        username: str | None,
        password: str | None,
        parser: ModemParser | None,
    ) -> DiscoveryResult:
        """Handle HNAP/SOAP session authentication.

        HNAP auth is handled by the existing HNAPSessionAuthStrategy.
        We detect it here and return HNAP_SESSION for the caller to handle.
        """
        if not username or not password:
            return self._error_result("HNAP authentication detected. Please provide credentials.")

        _LOGGER.debug("HNAP authentication detected")
        # HNAP requires the full strategy to execute the challenge-response
        # We return the strategy type; the caller uses AuthFactory to get the strategy
        return DiscoveryResult(
            success=True,
            strategy=AuthStrategyType.HNAP_SESSION,
            form_config=None,
            response_html=None,  # Will be fetched by strategy
            error_message=None,
            captured_response=None,
        )

    def _handle_js_auth(
        self,
        session: requests.Session,
        base_url: str,
        form_html: str,
        data_url: str,
        username: str | None,
        password: str | None,
        parser: ModemParser | None,
    ) -> DiscoveryResult:
        """Handle JavaScript-based authentication.

        Some modems (like SB8200) have forms that use JavaScript for submission
        instead of standard form submission. We check for parser hints.
        """
        # Check for parser hints (parser may be None in discovery-only mode)
        js_auth_hints = getattr(parser, "js_auth_hints", None) if parser else None
        if js_auth_hints:
            pattern = js_auth_hints.get("pattern")
            if pattern == "url_token_session":
                _LOGGER.debug("JavaScript auth detected with parser hint: url_token_session")
                return DiscoveryResult(
                    success=True,
                    strategy=AuthStrategyType.URL_TOKEN_SESSION,
                    form_config=None,
                    response_html=None,
                    error_message=None,
                    captured_response=None,
                )

        # No hints - we can't handle this JavaScript auth
        _LOGGER.debug("JavaScript form detected but no parser hints available")
        return self._error_result(
            "JavaScript-based login detected but not supported for this modem. "
            "Please submit diagnostics to help us add support."
        )

    def _handle_redirect(
        self,
        session: requests.Session,
        base_url: str,
        redirect_url: str,
        data_url: str,
        username: str | None,
        password: str | None,
        parser: ModemParser | None,
        redirect_count: int,
    ) -> DiscoveryResult:
        """Follow redirect and inspect the destination."""
        if not redirect_url:
            return self._error_result("Redirect detected but could not extract URL.")

        _LOGGER.debug("Following redirect to: %s", redirect_url)

        try:
            response = session.get(redirect_url, timeout=10, allow_redirects=False)
        except Exception as e:
            return self._error_result(f"Failed to follow redirect: {e}")

        # Re-inspect the redirected response
        return self._handle_response(
            response=response,
            session=session,
            base_url=base_url,
            data_url=data_url,
            username=username,
            password=password,
            parser=parser,
            redirect_count=redirect_count,
        )

    def _parse_login_form(self, html: str, parser: ModemParser | None) -> DiscoveredFormConfig | None:
        """Extract form configuration from login page HTML."""
        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form")
        if not form:
            return None

        # Get parser overrides if any (parser may be None in discovery-only mode)
        hints = getattr(parser, "auth_form_hints", {}) if parser else {}

        # Find username field
        username_field = hints.get("username_field") or self._find_username_field(form)
        if not username_field:
            _LOGGER.debug("Could not find username field in form")
            return None

        # Find password field
        password_field = hints.get("password_field") or self._find_password_field(form)
        if not password_field:
            _LOGGER.debug("Could not find password field in form")
            return None

        # Get form action and method
        action = form.get("action", "")
        method = form.get("method", "POST")

        # Collect hidden fields
        hidden_fields = {}
        for inp in form.find_all("input", {"type": "hidden"}):
            name = inp.get("name")
            if name:
                hidden_fields[name] = inp.get("value", "")

        return DiscoveredFormConfig(
            action=action,
            method=method,
            username_field=username_field,
            password_field=password_field,
            hidden_fields=hidden_fields,
        )

    def _find_username_field(self, form) -> str | None:
        """Find username field using generic hints."""
        # First, look for type="text" with username-like name
        for inp in form.find_all("input", {"type": "text"}):
            name = (inp.get("name") or "").lower()
            if any(hint in name for hint in self.USERNAME_HINTS):
                field_name = inp.get("name")
                return str(field_name) if field_name else None

        # Fallback: first text input
        first_text = form.find("input", {"type": "text"})
        if first_text:
            field_name = first_text.get("name")
            return str(field_name) if field_name else None

        return None

    def _find_password_field(self, form) -> str | None:
        """Find password field - type='password' is definitive."""
        pwd_input = form.find("input", {"type": "password"})
        if pwd_input:
            field_name = pwd_input.get("name")
            return str(field_name) if field_name else None
        return None

    def _is_login_form(self, html: str) -> bool:
        """Detect if HTML contains a login form."""
        if not html:
            return False
        soup = BeautifulSoup(html, "html.parser")
        # Must have a form with password field
        form = soup.find("form")
        if not form:
            return False
        return form.find("input", {"type": "password"}) is not None

    def _is_js_form(self, html: str) -> bool:
        """Detect if form uses JavaScript submission instead of normal submit."""
        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form")
        if not form:
            return False

        # Check for type="button" instead of type="submit"
        has_button = form.find("input", {"type": "button"}) is not None
        has_submit = form.find("input", {"type": "submit"}) is not None

        # If there's a button but no submit, it's probably JS-based
        if has_button and not has_submit:
            return True

        # Check for empty or missing action (often indicates JS handling)
        action = form.get("action", "").strip()
        return not action

    def _is_hnap_page(self, html: str) -> bool:
        """Detect HNAP by checking for SOAPAction.js script."""
        if not html:
            return False
        soup = BeautifulSoup(html, "html.parser")
        for script in soup.find_all("script", src=True):
            src = script.get("src", "").lower()
            if any(pattern in src for pattern in self.HNAP_SCRIPT_PATTERNS):
                return True
        return False

    def _is_redirect(self, response: requests.Response) -> bool:
        """Check if response is a redirect."""
        # HTTP redirects
        if response.status_code in (301, 302, 303, 307, 308):
            return True
        # Meta refresh redirect
        if response.status_code == 200 and response.text:
            lower_text = response.text.lower()
            if (
                "meta" in lower_text
                and "http-equiv" in lower_text
                and ('content="0;url=' in lower_text or "content='0;url=" in lower_text)
            ):
                return True
        return False

    def _get_redirect_url(self, response: requests.Response, base_url: str) -> str:
        """Extract redirect URL from response."""
        # HTTP redirect
        if "Location" in response.headers:
            return self._resolve_url(base_url, response.headers["Location"])

        # Meta refresh
        if response.text:
            match = re.search(
                r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;url=([^"\'>\s]+)',
                response.text,
                re.IGNORECASE,
            )
            if match:
                return self._resolve_url(base_url, match.group(1))

        return ""

    def _can_parse_data(self, html: str, parser: ModemParser | None) -> bool:
        """Check if HTML contains parseable modem data.

        When parser is None (discovery-only mode), returns True to allow
        auth discovery to proceed without parser validation.
        """
        if not html:
            return False
        if parser is None:
            # No parser available - assume data is parseable (discovery-only mode)
            # This allows auth discovery to run before parser detection
            return True
        try:
            soup = BeautifulSoup(html, "html.parser")
            result = parser.parse(soup)
            # Must have at least some channel data
            downstream = result.get("downstream", [])
            upstream = result.get("upstream", [])
            return len(downstream) > 0 or len(upstream) > 0
        except Exception:
            return False

    def _resolve_url(self, base_url: str, path: str) -> str:
        """Resolve relative URL against base."""
        if path.startswith("http"):
            return path
        return urljoin(base_url + "/", path)

    def _error_result(self, message: str) -> DiscoveryResult:
        """Create error result."""
        return DiscoveryResult(
            success=False,
            strategy=None,
            form_config=None,
            response_html=None,
            error_message=message,
            captured_response=None,
        )

    def _unknown_result(self, response: requests.Response) -> DiscoveryResult:
        """Create result for unknown auth pattern - captures data for debugging."""
        return DiscoveryResult(
            success=False,
            strategy=AuthStrategyType.UNKNOWN,
            form_config=None,
            response_html=None,
            error_message="Unknown authentication protocol. Please submit diagnostics.",
            captured_response={
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "html_sample": response.text[:5000] if response.text else None,
                "url": str(response.url),
            },
        )

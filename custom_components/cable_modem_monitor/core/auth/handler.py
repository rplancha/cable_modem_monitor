"""Runtime authentication handler for polling.

This module applies stored authentication strategies during polling.
Unlike AuthDiscovery (which discovers strategies), AuthHandler applies
a known strategy to authenticate a session.

All authentication types are handled directly by AuthHandler - parsers
do not implement login() methods.

Usage:
    from custom_components.cable_modem_monitor.core.auth.handler import AuthHandler
    from custom_components.cable_modem_monitor.core.auth.types import AuthStrategyType

    handler = AuthHandler(
        strategy=AuthStrategyType.FORM_PLAIN,
        form_config=stored_form_config,
    )

    success, html = handler.authenticate(
        session=session,
        base_url="http://192.168.100.1",
        username="admin",
        password="password",
    )
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .types import AuthStrategyType

if TYPE_CHECKING:
    import requests

    from .hnap import HNAPJsonRequestBuilder

_LOGGER = logging.getLogger(__name__)

# Default HNAP configuration (works for most HNAP modems)
DEFAULT_HNAP_CONFIG = {
    "endpoint": "/HNAP1/",
    "namespace": "http://purenetworks.com/HNAP1/",
    "empty_action_value": {},  # MB8611 default
}

# Default URL token configuration (SB8200)
DEFAULT_URL_TOKEN_CONFIG = {
    "login_page": "/cmconnectionstatus.html",
    "login_prefix": "login_",
    "session_cookie_name": "credential",
    "data_page": "/cmconnectionstatus.html",
    "token_prefix": "ct_",
    "success_indicator": "Downstream",
}


class AuthHandler:
    """Applies stored authentication strategy during polling.

    This is the runtime counterpart to AuthDiscovery. While AuthDiscovery
    inspects responses to determine the auth strategy, AuthHandler applies
    a known strategy to authenticate a session.

    Supported strategies (all handled directly, no parser delegation):
    - NO_AUTH: No authentication needed
    - BASIC_HTTP: HTTP Basic Authentication
    - FORM_PLAIN: Standard form-based login
    - FORM_BASE64: Form with base64-encoded password
    - HNAP_SESSION: HNAP/SOAP authentication
    - URL_TOKEN_SESSION: URL-based token auth (SB8200)
    """

    def __init__(
        self,
        strategy: AuthStrategyType | str | None = None,
        form_config: dict[str, Any] | None = None,
        hnap_config: dict[str, Any] | None = None,
        url_token_config: dict[str, Any] | None = None,
    ):
        """Initialize auth handler.

        Args:
            strategy: The auth strategy to use (AuthStrategyType or string value)
            form_config: Form configuration for form-based auth (required for FORM_*)
            hnap_config: HNAP configuration (endpoint, namespace, empty_action_value)
            url_token_config: URL token configuration (login_page, etc.)
        """
        # Normalize strategy to AuthStrategyType
        if isinstance(strategy, str):
            try:
                # Handle case-insensitive matching (config may store uppercase)
                self.strategy = AuthStrategyType(strategy.lower())
            except ValueError:
                _LOGGER.warning("Unknown auth strategy string: %s, defaulting to UNKNOWN", strategy)
                self.strategy = AuthStrategyType.UNKNOWN
        elif strategy is None:
            self.strategy = AuthStrategyType.UNKNOWN
        else:
            self.strategy = strategy

        self.form_config = form_config or {}
        self.hnap_config = {**DEFAULT_HNAP_CONFIG, **(hnap_config or {})}
        self.url_token_config = {**DEFAULT_URL_TOKEN_CONFIG, **(url_token_config or {})}

        # HNAP builder instance (created on first auth, reused for data fetches)
        self._hnap_builder: HNAPJsonRequestBuilder | None = None

    def authenticate(
        self,
        session: requests.Session,
        base_url: str,
        username: str | None,
        password: str | None,
    ) -> tuple[bool, str | None]:
        """Authenticate the session using the stored strategy.

        Args:
            session: requests.Session to authenticate
            base_url: Modem base URL
            username: Username for authentication
            password: Password for authentication

        Returns:
            tuple of (success, authenticated_html)
            - success: True if authentication succeeded
            - authenticated_html: HTML from post-auth response (or None)
        """
        _LOGGER.debug("Authenticating with strategy: %s", self.strategy.value)

        if self.strategy == AuthStrategyType.NO_AUTH:
            return self._handle_no_auth()

        if self.strategy == AuthStrategyType.BASIC_HTTP:
            return self._handle_basic_auth(session, base_url, username, password)

        if self.strategy in (AuthStrategyType.FORM_PLAIN, AuthStrategyType.FORM_BASE64):
            return self._handle_form_auth(session, base_url, username, password)

        if self.strategy == AuthStrategyType.HNAP_SESSION:
            return self._handle_hnap_auth(session, base_url, username, password)

        if self.strategy == AuthStrategyType.URL_TOKEN_SESSION:
            return self._handle_url_token_auth(session, base_url, username, password)

        # Unknown strategy - return success to allow data fetch attempt
        _LOGGER.warning(
            "Unknown auth strategy: %s - attempting without auth",
            self.strategy.value,
        )
        return True, None

    def _handle_no_auth(self) -> tuple[bool, str | None]:
        """Handle NO_AUTH strategy - nothing to do."""
        _LOGGER.debug("No authentication required")
        return True, None

    def _handle_basic_auth(
        self,
        session: requests.Session,
        base_url: str,
        username: str | None,
        password: str | None,
    ) -> tuple[bool, str | None]:
        """Handle HTTP Basic Authentication.

        Sets session.auth for all subsequent requests.
        """
        if not username or not password:
            _LOGGER.warning("Basic auth configured but no credentials provided")
            return False, None

        session.auth = (username, password)
        _LOGGER.debug("Basic auth credentials set on session")

        # Verify auth works by fetching base URL
        try:
            response = session.get(base_url, timeout=10)
            if response.status_code == 200:
                _LOGGER.debug("Basic auth verified successfully")
                return True, response.text
            elif response.status_code == 401:
                _LOGGER.warning("Basic auth failed - invalid credentials (401)")
                session.auth = None
                return False, None
            else:
                _LOGGER.debug("Basic auth response: %d", response.status_code)
                return True, response.text
        except Exception as e:
            _LOGGER.warning("Basic auth verification failed: %s", e)
            return False, None

    def _handle_form_auth(
        self,
        session: requests.Session,
        base_url: str,
        username: str | None,
        password: str | None,
    ) -> tuple[bool, str | None]:
        """Handle form-based authentication.

        Uses stored form_config to submit login form.
        """
        if not username or not password:
            _LOGGER.warning("Form auth configured but no credentials provided")
            return False, None

        if not self.form_config:
            _LOGGER.warning("Form auth configured but no form_config provided")
            return False, None

        # Extract form configuration
        action = self.form_config.get("action", "")
        method = self.form_config.get("method", "POST").upper()
        username_field = self.form_config.get("username_field", "username")
        password_field = self.form_config.get("password_field", "password")
        hidden_fields = self.form_config.get("hidden_fields", {})

        # Encode password if using FORM_BASE64 strategy
        encoded_password = password
        if self.strategy == AuthStrategyType.FORM_BASE64 and password:
            import base64

            encoded_password = base64.b64encode(password.encode("utf-8")).decode("utf-8")
            _LOGGER.debug("Password encoded with base64 for FORM_BASE64 strategy")

        # Build form data
        form_data = {
            username_field: username,
            password_field: encoded_password,
            **hidden_fields,
        }

        # Resolve action URL
        action_url = self._resolve_url(base_url, action)
        _LOGGER.debug(
            "Submitting form to %s (method=%s, user_field=%s)",
            action_url,
            method,
            username_field,
        )

        try:
            if method == "POST":
                response = session.post(action_url, data=form_data, timeout=10)
            else:
                response = session.get(action_url, params=form_data, timeout=10)

            _LOGGER.debug("Form submission response: %d", response.status_code)

            # Check if we got redirected back to login (auth failed)
            if self._is_login_page(response.text):
                _LOGGER.warning("Form auth failed - still on login page")
                return False, None

            # Fetch base URL to get authenticated HTML
            data_response = session.get(base_url, timeout=10)
            if data_response.status_code == 200:
                _LOGGER.debug("Form auth successful")
                return True, data_response.text

            return True, response.text

        except Exception as e:
            _LOGGER.warning("Form auth failed: %s", e)
            return False, None

    def _resolve_url(self, base_url: str, path: str) -> str:
        """Resolve relative URL against base."""
        if path.startswith("http"):
            return path
        from urllib.parse import urljoin

        return urljoin(base_url + "/", path)

    def _is_login_page(self, html: str | None) -> bool:
        """Check if HTML appears to be a login page."""
        if not html:
            return False
        lower = html.lower()
        # Look for password field - strong indicator of login form
        return 'type="password"' in lower or "type='password'" in lower

    def _handle_hnap_auth(
        self,
        session: requests.Session,
        base_url: str,
        username: str | None,
        password: str | None,
    ) -> tuple[bool, str | None]:
        """Handle HNAP/SOAP authentication.

        Creates HNAPJsonRequestBuilder and performs challenge-response login.
        The builder is stored for reuse during data fetches.
        """
        if not username or not password:
            _LOGGER.warning("HNAP auth configured but no credentials provided")
            return False, None

        # Import here to avoid circular imports
        from .hnap import HNAPJsonRequestBuilder

        # Create builder with stored config
        self._hnap_builder = HNAPJsonRequestBuilder(
            endpoint=self.hnap_config["endpoint"],
            namespace=self.hnap_config["namespace"],
            empty_action_value=self.hnap_config.get("empty_action_value", {}),
        )

        _LOGGER.debug(
            "HNAP auth: endpoint=%s, namespace=%s",
            self.hnap_config["endpoint"],
            self.hnap_config["namespace"],
        )

        try:
            success, response_text = self._hnap_builder.login(session, base_url, username, password)

            if success:
                _LOGGER.debug("HNAP authentication successful")
                return True, response_text
            else:
                _LOGGER.warning("HNAP authentication failed")
                self._hnap_builder = None
                return False, response_text

        except Exception as e:
            _LOGGER.warning("HNAP auth failed with exception: %s", e)
            self._hnap_builder = None
            return False, None

    def _handle_url_token_auth(
        self,
        session: requests.Session,
        base_url: str,
        username: str | None,
        password: str | None,
    ) -> tuple[bool, str | None]:
        """Handle URL-based token authentication with session cookie.

        Used by modems like ARRIS SB8200 that use base64 credentials in URL.
        """
        import base64

        if not username or not password:
            _LOGGER.debug("No credentials provided for URL token auth, skipping")
            return True, None

        config = self.url_token_config

        try:
            # Build base64 token: base64(username:password)
            credentials = f"{username}:{password}"
            token = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

            # Build login URL with token parameter
            login_url = f"{base_url}{config['login_page']}?{config['login_prefix']}{token}"
            _LOGGER.debug("URL token auth: Attempting login to %s", base_url)

            # Include Authorization header (required by some firmware)
            headers = {"Authorization": f"Basic {token}"}

            # Make login request
            response = session.get(login_url, headers=headers, timeout=10, verify=False)

            if response.status_code != 200:
                _LOGGER.warning("URL token auth: Login returned status %d", response.status_code)
                return False, None

            # Check if we got data directly in login response
            if config["success_indicator"] in response.text:
                _LOGGER.info("URL token auth: Got data directly from login")
                return True, response.text

            # Try to get session token from cookie
            session_token = session.cookies.get(config["session_cookie_name"])
            if not session_token:
                _LOGGER.warning("URL token auth: No session cookie received")
                return True, None  # Return success to allow fallback

            _LOGGER.debug("URL token auth: Got session cookie, fetching data page")

            # Fetch data page with session token
            data_url = f"{base_url}{config['data_page']}?{config['token_prefix']}{session_token}"
            data_response = session.get(data_url, headers=headers, timeout=10, verify=False)

            if data_response.status_code == 200 and config["success_indicator"] in data_response.text:
                _LOGGER.info("URL token auth: Authentication successful")
                return True, data_response.text

            _LOGGER.warning(
                "URL token auth: Data fetch returned %d, has indicator: %s",
                data_response.status_code,
                config["success_indicator"] in data_response.text,
            )
            return True, None  # Return success to allow fallback

        except Exception as e:
            _LOGGER.error("URL token auth: Error during login: %s", e)
            return False, None

    def get_hnap_builder(self) -> HNAPJsonRequestBuilder | None:
        """Get the HNAP builder for data fetches after authentication.

        Returns the HNAPJsonRequestBuilder instance if HNAP auth was used,
        or None otherwise. The scraper can use this for HNAP data fetches.
        """
        return self._hnap_builder

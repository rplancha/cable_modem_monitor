"""Pytest fixtures for integration tests with mock HTTP/HTTPS servers.

These fixtures provide real servers for testing SSL/TLS behavior,
including legacy cipher support and certificate handling.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import socket
import ssl
import tempfile
import threading
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

# Test response HTML (minimal modem-like response)
MOCK_MODEM_RESPONSE = b"""<!DOCTYPE html>
<html>
<head><title>Cable Modem Status</title></head>
<body>
<h1>Cable Modem Status</h1>
<table id="downstream">
<tr><td>Channel 1</td><td>32</td><td>-1.0 dBmV</td><td>39.0 dB</td></tr>
</table>
</body>
</html>
"""


class MockModemHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler that returns mock modem status page."""

    def log_message(self, format, *args):
        """Suppress logging during tests."""
        pass

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET requests."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(MOCK_MODEM_RESPONSE)))
        self.end_headers()
        self.wfile.write(MOCK_MODEM_RESPONSE)


def _find_free_port() -> int:
    """Find an available port for the test server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def _generate_self_signed_cert(cert_dir: str) -> tuple[str, str]:
    """Generate a self-signed certificate for testing.

    Returns:
        Tuple of (cert_path, key_path)
    """
    from datetime import datetime, timedelta

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        pytest.skip("cryptography package required for SSL tests")

    # Generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Generate certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cable Modem Monitor Tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Write cert and key to files
    cert_path = os.path.join(cert_dir, "cert.pem")
    key_path = os.path.join(cert_dir, "key.pem")

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    return cert_path, key_path


class MockServer:
    """Wrapper for test HTTP/HTTPS server with lifecycle management."""

    def __init__(
        self,
        port: int,
        ssl_context: ssl.SSLContext | None = None,
        handler_class: type = MockModemHandler,
    ):
        self.port = port
        self.ssl_context = ssl_context
        self.handler_class = handler_class
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        """Get the server URL."""
        scheme = "https" if self.ssl_context else "http"
        return f"{scheme}://127.0.0.1:{self.port}"

    def start(self):
        """Start the server in a background thread."""
        self._server = HTTPServer(("127.0.0.1", self.port), self.handler_class)

        if self.ssl_context:
            self._server.socket = self.ssl_context.wrap_socket(
                self._server.socket,
                server_side=True,
            )

        self._thread = threading.Thread(target=self._server.serve_forever)
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        """Stop the server."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)


@pytest.fixture(scope="session")
def test_certs() -> Generator[tuple[str, str], None, None]:
    """Generate self-signed certificates for HTTPS testing.

    Yields:
        Tuple of (cert_path, key_path)
    """
    with tempfile.TemporaryDirectory() as cert_dir:
        cert_path, key_path = _generate_self_signed_cert(cert_dir)
        yield cert_path, key_path


@pytest.fixture
def http_server() -> Generator[MockServer, None, None]:
    """Provide a plain HTTP server (no SSL).

    Use this to verify that LegacySSLAdapter is NOT mounted for HTTP URLs.
    """
    port = _find_free_port()
    server = MockServer(port=port, ssl_context=None)
    server.start()
    yield server
    server.stop()


@pytest.fixture
def https_modern_server(test_certs) -> Generator[MockServer, None, None]:
    """Provide an HTTPS server with modern ciphers (default SSL context).

    Use this to verify that connections work with default settings.
    """
    cert_path, key_path = test_certs
    port = _find_free_port()

    # Modern SSL context with default (secure) settings
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    server = MockServer(port=port, ssl_context=context)
    server.start()
    yield server
    server.stop()


@pytest.fixture
def https_legacy_server(test_certs) -> Generator[MockServer, None, None]:
    """Provide an HTTPS server that ONLY accepts legacy ciphers.

    This simulates older modem firmware that requires SECLEVEL=0.
    Use this to verify that LegacySSLAdapter works correctly.
    """
    cert_path, key_path = test_certs
    port = _find_free_port()

    # Legacy SSL context - only accepts weak ciphers
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    # Set to only accept legacy ciphers that modern clients reject by default
    # This simulates old modem firmware behavior
    # DES-CBC3-SHA is a legacy cipher that requires SECLEVEL=0 on modern Python
    try:
        context.set_ciphers("DES-CBC3-SHA")
    except ssl.SSLError:
        # If the cipher isn't available, use any legacy cipher
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
        # Then restrict further if possible
        with contextlib.suppress(ssl.SSLError):
            context.set_ciphers("3DES:@SECLEVEL=0")

    server = MockServer(port=port, ssl_context=context)
    server.start()
    yield server
    server.stop()


@pytest.fixture
def https_self_signed_server(test_certs) -> Generator[MockServer, None, None]:
    """Provide an HTTPS server with self-signed certificate.

    Use this to verify that verify=False works correctly.
    Same as https_modern_server but explicitly named for clarity.
    """
    cert_path, key_path = test_certs
    port = _find_free_port()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    server = MockServer(port=port, ssl_context=context)
    server.start()
    yield server
    server.stop()


# =============================================================================
# SB8200 Auth Mock Server
# =============================================================================

# Load SB8200 fixture HTML
_SB8200_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "parsers",
    "arris",
    "fixtures",
    "sb8200",
    "cmconnectionstatus.html",
)


def _load_sb8200_fixture() -> bytes:
    """Load SB8200 fixture HTML."""
    # Use Windows-1252 encoding (fixture has copyright symbol)
    with open(_SB8200_FIXTURE_PATH, encoding="cp1252") as f:
        return f.read().encode("utf-8")


class SB8200MockHandler(BaseHTTPRequestHandler):
    """Mock SB8200 modem with configurable auth modes.

    Class attributes control behavior:
        require_auth: If True, requires URL-based auth (Travis's variant)
        valid_credentials: Expected "user:password" string
    """

    require_auth = False
    valid_credentials = "admin:password"
    _fixture_html: bytes | None = None

    def log_message(self, format, *args):
        """Suppress logging during tests."""
        pass

    @classmethod
    def get_fixture_html(cls) -> bytes:
        """Lazy-load and cache fixture HTML."""
        if cls._fixture_html is None:
            cls._fixture_html = _load_sb8200_fixture()
        return cls._fixture_html

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET requests with optional auth."""
        import base64

        # No-auth mode (Tim's variant) - serve pages directly
        if not self.require_auth:
            self._serve_status_page()
            return

        # Auth mode (Travis's variant)
        if "login_" in self.path:
            # Extract and validate base64 credentials from URL
            try:
                token = self.path.split("login_")[1].split("&")[0].split("?")[0]
                decoded = base64.b64decode(token).decode("utf-8")
                if decoded == self.valid_credentials:
                    self._serve_status_page()
                    return
            except Exception:
                pass
            self._send_401()
        elif self.path == "/" or self.path == "":
            # Root page - serve login page (or minimal response for detection)
            self._serve_login_page()
        else:
            # Any other page without auth - 401
            self._send_401()

    def _serve_status_page(self) -> None:
        """Serve the SB8200 status page fixture."""
        content = self.get_fixture_html()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _serve_login_page(self) -> None:
        """Serve minimal login page with model detection span."""
        content = b"""<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<span id="thisModelNumberIs">SB8200</span>
<form action="">
<input type="text" id="username" name="username">
<input type="password" id="password" name="password">
<input type="button" id="loginButton" value="Login">
</form>
</body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_401(self) -> None:
        """Send 401 Unauthorized response."""
        content = b"Unauthorized"
        self.send_response(401)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


@pytest.fixture
def sb8200_server_noauth() -> Generator[MockServer, None, None]:
    """Provide SB8200 mock server without auth (Tim's variant).

    This simulates older firmware that doesn't require login.
    """
    SB8200MockHandler.require_auth = False
    port = _find_free_port()
    server = MockServer(port=port, ssl_context=None, handler_class=SB8200MockHandler)
    server.start()
    yield server
    server.stop()


@pytest.fixture
def sb8200_server_auth() -> Generator[MockServer, None, None]:
    """Provide SB8200 mock server with URL-based auth (Travis's variant).

    This simulates newer firmware that requires login via URL query param:
    /cmconnectionstatus.html?login_<base64(user:pass)>
    """
    SB8200MockHandler.require_auth = True
    SB8200MockHandler.valid_credentials = "admin:password"
    port = _find_free_port()
    server = MockServer(port=port, ssl_context=None, handler_class=SB8200MockHandler)
    server.start()
    yield server
    server.stop()


@pytest.fixture
def sb8200_server_auth_https(test_certs) -> Generator[MockServer, None, None]:
    """Provide SB8200 mock server with HTTPS + auth (full Travis scenario).

    This simulates the complete scenario: HTTPS with self-signed cert + auth.
    """
    SB8200MockHandler.require_auth = True
    SB8200MockHandler.valid_credentials = "admin:password"

    cert_path, key_path = test_certs
    port = _find_free_port()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    server = MockServer(port=port, ssl_context=context, handler_class=SB8200MockHandler)
    server.start()
    yield server
    server.stop()


# =============================================================================
# Auth Discovery Mock Servers
# =============================================================================


class BasicAuthMockHandler(BaseHTTPRequestHandler):
    """Mock server requiring HTTP Basic Auth."""

    valid_credentials = ("admin", "password")

    def log_message(self, format, *args):
        """Suppress logging during tests."""
        pass

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET with Basic Auth check."""
        import base64

        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            try:
                token = auth_header.split(" ", 1)[1]
                decoded = base64.b64decode(token).decode("utf-8")
                username, password = decoded.split(":", 1)
                if (username, password) == self.valid_credentials:
                    self._serve_data_page()
                    return
            except Exception:
                pass

        # Return 401 Unauthorized with WWW-Authenticate header
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Modem"')
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Unauthorized")

    def _serve_data_page(self) -> None:
        """Serve modem data page."""
        content = MOCK_MODEM_RESPONSE
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


class FormAuthMockHandler(BaseHTTPRequestHandler):
    """Mock server with form-based authentication."""

    valid_username = "admin"
    valid_password = "password"
    authenticated_sessions: set = set()

    def log_message(self, format, *args):
        """Suppress logging during tests."""
        pass

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET requests."""
        # Check session cookie
        cookies = self.headers.get("Cookie", "")
        if "session=authenticated" in cookies or self._check_session(cookies):
            self._serve_data_page()
        else:
            self._serve_login_form()

    def do_POST(self) -> None:  # noqa: N802
        """Handle POST (form submission)."""
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")

        # Parse form data
        from urllib.parse import parse_qs

        params = parse_qs(post_data)
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]

        if username == self.valid_username and password == self.valid_password:
            # Set session cookie and redirect to data page
            import uuid

            session_id = str(uuid.uuid4())
            self.authenticated_sessions.add(session_id)
            self.send_response(302)
            self.send_header("Location", "/status.html")
            self.send_header("Set-Cookie", f"session={session_id}; Path=/")
            self.end_headers()
        else:
            # Return login form again (wrong creds)
            self._serve_login_form()

    def _check_session(self, cookies: str) -> bool:
        """Check if session cookie is valid."""
        for cookie in cookies.split(";"):
            if "session=" in cookie:
                session_id = cookie.split("=", 1)[1].strip()
                return session_id in self.authenticated_sessions
        return False

    def _serve_login_form(self) -> None:
        """Serve login form."""
        content = b"""<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<form action="/login" method="POST">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="hidden" name="csrf_token" value="test-csrf-token">
    <input type="submit" value="Login">
</form>
</body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _serve_data_page(self) -> None:
        """Serve modem data page."""
        content = MOCK_MODEM_RESPONSE
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


class HNAPAuthMockHandler(BaseHTTPRequestHandler):
    """Mock server with HNAP/SOAP authentication (like S33/MB8611)."""

    def log_message(self, format, *args):
        """Suppress logging during tests."""
        pass

    def do_GET(self) -> None:  # noqa: N802
        """Serve HNAP login page with SOAPAction.js script."""
        if self.path == "/" or "Login" in self.path:
            self._serve_hnap_login_page()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_hnap_login_page(self) -> None:
        """Serve login page with HNAP detection scripts."""
        content = b"""<!DOCTYPE html>
<html><head>
<title>Login</title>
<script type="text/javascript" src="js/SOAP/SOAPAction.js"></script>
<script type="text/javascript" src="js/Login.js"></script>
</head>
<body>
<form id="loginForm">
    <input type="text" id="username" name="username">
    <input type="password" id="password" name="password">
    <button type="button" onclick="doLogin()">Login</button>
</form>
</body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


class RedirectAuthMockHandler(BaseHTTPRequestHandler):
    """Mock server that uses meta refresh redirect to login page."""

    authenticated = False

    def log_message(self, format, *args):
        """Suppress logging during tests."""
        pass

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET with redirect to login."""
        if self.path == "/login":
            self._serve_login_form()
        elif self.path == "/status":
            cookies = self.headers.get("Cookie", "")
            if "session=authenticated" in cookies:
                self._serve_data_page()
            else:
                self._serve_meta_refresh_redirect()
        else:
            self._serve_meta_refresh_redirect()

    def do_POST(self) -> None:  # noqa: N802
        """Handle form submission."""
        self.send_response(302)
        self.send_header("Location", "/status")
        self.send_header("Set-Cookie", "session=authenticated; Path=/")
        self.end_headers()

    def _serve_meta_refresh_redirect(self) -> None:
        """Serve page with meta refresh redirect."""
        content = b'<html><head><meta http-equiv="refresh" content="0;url=/login"></head></html>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _serve_login_form(self) -> None:
        """Serve login form."""
        content = b"""<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<form action="/login" method="POST">
    <input type="text" name="user" placeholder="Username">
    <input type="password" name="pass" placeholder="Password">
    <input type="submit" value="Login">
</form>
</body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _serve_data_page(self) -> None:
        """Serve modem data page."""
        content = MOCK_MODEM_RESPONSE
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


@pytest.fixture
def basic_auth_server() -> Generator[MockServer, None, None]:
    """Provide mock server requiring HTTP Basic Auth."""
    port = _find_free_port()
    server = MockServer(port=port, ssl_context=None, handler_class=BasicAuthMockHandler)
    server.start()
    yield server
    server.stop()


@pytest.fixture
def form_auth_server() -> Generator[MockServer, None, None]:
    """Provide mock server with form-based authentication."""
    FormAuthMockHandler.authenticated_sessions = set()
    port = _find_free_port()
    server = MockServer(port=port, ssl_context=None, handler_class=FormAuthMockHandler)
    server.start()
    yield server
    server.stop()


@pytest.fixture
def hnap_auth_server() -> Generator[MockServer, None, None]:
    """Provide mock server with HNAP-style login page."""
    port = _find_free_port()
    server = MockServer(port=port, ssl_context=None, handler_class=HNAPAuthMockHandler)
    server.start()
    yield server
    server.stop()


@pytest.fixture
def redirect_auth_server() -> Generator[MockServer, None, None]:
    """Provide mock server with meta refresh redirect to login."""
    port = _find_free_port()
    server = MockServer(port=port, ssl_context=None, handler_class=RedirectAuthMockHandler)
    server.start()
    yield server
    server.stop()

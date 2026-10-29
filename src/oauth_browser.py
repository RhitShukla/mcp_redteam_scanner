"""
Browser-based OAuth 2.0 Authorization Code flow with PKCE.

1. Discovers OAuth endpoints from the MCP server
2. Registers as a dynamic client
3. Opens the browser for login
4. Captures the authorization code via local callback
5. Exchanges the code for an access token
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import urllib.parse
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler

import httpx


class _CallbackHandler(BaseHTTPRequestHandler):
    """Captures the OAuth authorization code from the redirect."""

    code: str | None = None
    error: str | None = None
    received = threading.Event()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if "code" in params:
            _CallbackHandler.code = params["code"][0]
            self._serve_success()
        elif "error" in params:
            _CallbackHandler.error = params.get("error_description", params["error"])[0]
            self._serve_error(_CallbackHandler.error)
        else:
            self._serve_error("No authorization code received")

        _CallbackHandler.received.set()

    def _serve_success(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"<html><body><h2>Login successful!</h2>"
            b"<p>You can close this tab and return to the terminal.</p>"
            b"</body></html>"
        )

    def _serve_error(self, message: str):
        self.send_response(400)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            f"<html><body><h2>Login failed</h2><p>{message}</p></body></html>".encode()
        )

    def log_message(self, format, *args):
        pass


def _generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256)."""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _discover_oauth_metadata(mcp_endpoint: str) -> dict:
    """Fetch OAuth metadata from the MCP server's authorization server."""
    # Derive base URL from MCP endpoint
    parsed = urllib.parse.urlparse(mcp_endpoint)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # Try MCP server's well-known endpoint first
    metadata_url = f"{base_url}/.well-known/oauth-authorization-server"
    resp = httpx.get(metadata_url, follow_redirects=True, timeout=10)

    if resp.status_code == 200:
        try:
            return resp.json()
        except json.JSONDecodeError:
            pass

    raise RuntimeError(
        f"Could not discover OAuth metadata from {metadata_url} "
        f"(status: {resp.status_code})"
    )


def _register_client(
    registration_endpoint: str,
    redirect_uri: str,
) -> str:
    """Dynamically register an OAuth client and return the client_id."""
    resp = httpx.post(
        registration_endpoint,
        json={
            "client_name": "MCP RedTeam Scanner",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": "mcp:access",
        },
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["client_id"]


def _exchange_code_for_token(
    token_endpoint: str,
    code: str,
    redirect_uri: str,
    client_id: str,
    code_verifier: str,
    resource: str | None = None,
) -> str:
    """Exchange the authorization code for an access token."""
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    if resource:
        body["resource"] = resource

    resp = httpx.post(
        token_endpoint,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()

    if "access_token" not in data:
        raise RuntimeError(f"Token response missing access_token: {data}")

    return data["access_token"]


def browser_login(
    mcp_endpoint: str,
    auth_server: str | None = None,
    callback_port: int = 8765,
    timeout: int = 300,
) -> str:
    """
    Full OAuth 2.0 Authorization Code + PKCE flow via browser.

    Args:
        mcp_endpoint: The MCP SSE endpoint URL.
        auth_server: Override for the auth server base URL.
                     If None, discovered from MCP server metadata.
        callback_port: Local port for the OAuth callback server.
        timeout: Seconds to wait for login before giving up.

    Returns:
        The access token string (Bearer token for the MCP endpoint).
    """
    redirect_uri = f"http://localhost:{callback_port}/callback"

    # Step 1: Discover OAuth metadata
    if auth_server:
        metadata_url = f"{auth_server}/.well-known/oauth-authorization-server"
        print(f"[*] Fetching OAuth metadata from {metadata_url}")
        resp = httpx.get(metadata_url, follow_redirects=True, timeout=10)
        resp.raise_for_status()
        metadata = resp.json()
    else:
        print(f"[*] Discovering OAuth metadata from MCP endpoint...")
        metadata = _discover_oauth_metadata(mcp_endpoint)

    authorization_endpoint = metadata["authorization_endpoint"]
    token_endpoint = metadata["token_endpoint"]
    registration_endpoint = metadata.get("registration_endpoint")

    print(f"[+] Authorization endpoint: {authorization_endpoint}")
    print(f"[+] Token endpoint: {token_endpoint}")

    # Step 2: Register client dynamically
    if registration_endpoint:
        print(f"[*] Registering OAuth client...")
        client_id = _register_client(registration_endpoint, redirect_uri)
        print(f"[+] Client ID: {client_id}")
    else:
        raise RuntimeError(
            "No registration endpoint found and no client_id provided. "
            "The auth server does not support dynamic client registration."
        )

    # Step 3: Generate PKCE
    code_verifier, code_challenge = _generate_pkce()

    # Step 4: Build authorization URL
    parsed_mcp = urllib.parse.urlparse(mcp_endpoint)
    resource_url = f"{parsed_mcp.scheme}://{parsed_mcp.netloc}/"
    state = base64.urlsafe_b64encode(os.urandom(24)).rstrip(b"=").decode()

    auth_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "scope": "mcp:access",
        "resource": resource_url,
    }
    auth_url = f"{authorization_endpoint}?{urllib.parse.urlencode(auth_params)}"

    # Step 5: Start local callback server
    _CallbackHandler.code = None
    _CallbackHandler.error = None
    _CallbackHandler.received = threading.Event()

    server = HTTPServer(("127.0.0.1", callback_port), _CallbackHandler)

    def serve_until_done():
        while not _CallbackHandler.received.is_set():
            server.handle_request()

    serve_thread = threading.Thread(target=serve_until_done, daemon=True)
    serve_thread.start()

    # Step 6: Open browser
    print(f"\n[*] Opening browser for login...")
    print(f"    {auth_url}\n")
    webbrowser.open(auth_url)

    # Step 7: Wait for callback
    print(f"[*] Waiting for login (timeout: {timeout}s)...")
    serve_thread.join(timeout=timeout)
    server.server_close()

    if _CallbackHandler.error:
        raise RuntimeError(f"OAuth error: {_CallbackHandler.error}")

    if not _CallbackHandler.code:
        raise TimeoutError(f"No login callback received within {timeout} seconds.")

    print(f"[+] Authorization code received.")

    # Step 8: Exchange code for access token
    print(f"[*] Exchanging code for access token...")
    access_token = _exchange_code_for_token(
        token_endpoint=token_endpoint,
        code=_CallbackHandler.code,
        redirect_uri=redirect_uri,
        client_id=client_id,
        code_verifier=code_verifier,
        resource=resource_url,
    )
    print(f"[+] Access token obtained.\n")
    
    return access_token

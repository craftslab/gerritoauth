#!/usr/bin/env python3
"""
Fake UAC OAuth Provider Service for Testing Gerrit OAuth Plugin

This service implements a minimal OAuth 2.0 provider that matches the
requirements of the Gerrit OAuth plugin for testing purposes.

Endpoints:
- GET /oauth/authorize - Authorization endpoint
- POST /oauth/token - Token endpoint
- GET /api/user - User info endpoint

Usage:
    python3 fake_oauth_provider.py [--port PORT] [--host HOST]

Default: http://localhost:8000

Environment Variables:
    OAUTH_CLIENT_ID       - OAuth client ID (default: your-client-id)
    OAUTH_CLIENT_SECRET   - OAuth client secret (default: your-client-secret)

Note: These values must match the client-id and client-secret in gerrit.config
"""

import argparse
import json
import os
import secrets
import time
from urllib.parse import parse_qs, urlparse, urlencode
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Optional

# Configuration - can be overridden via environment variables
# These should match the values in gerrit.config [plugin "oauth-uac-oauth"] section
DEFAULT_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "your-client-id")
DEFAULT_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", "your-client-secret")

# In-memory storage for authorization codes and tokens
authorization_codes: Dict[str, dict] = {}  # code -> {client_id, redirect_uri, expires_at}
access_tokens: Dict[str, dict] = {}  # token -> {client_id, user_id, expires_at}

# Default test user
DEFAULT_USER = {
    "id": "12345",
    "email": "testuser@example.com",
    "login": "testuser",
    "name": "Test User"
}


class OAuthRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for OAuth endpoints"""

    def log_message(self, format, *args):
        """Override to add custom logging format"""
        print(f"[{self.address_string()}] {format % args}")

    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == "/oauth/authorize":
            self.handle_authorize(parsed_path.query)
        elif path == "/api/user":
            self.handle_user_info()
        elif path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
            <html>
            <head><title>Fake UAC OAuth Provider</title></head>
            <body>
                <h1>Fake UAC OAuth Provider</h1>
                <p>This is a fake OAuth provider for testing the Gerrit OAuth plugin.</p>
                <h2>Endpoints:</h2>
                <ul>
                    <li><code>GET /oauth/authorize</code> - Authorization endpoint</li>
                    <li><code>POST /oauth/token</code> - Token endpoint</li>
                    <li><code>GET /api/user</code> - User info endpoint</li>
                </ul>
            </body>
            </html>
            """)
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == "/oauth/token":
            self.handle_token()
        else:
            self.send_error(404, "Not Found")

    def handle_authorize(self, query_string: str):
        """Handle OAuth authorization request"""
        try:
            params = parse_qs(query_string)
            client_id = params.get("client_id", [None])[0]
            redirect_uri = params.get("redirect_uri", [None])[0]
            response_type = params.get("response_type", [None])[0]
            state = params.get("state", [None])[0]

            # Log the authorization request details
            self.log_message(f"Authorization request received:")
            self.log_message(f"  - client_id: {client_id}")
            self.log_message(f"  - redirect_uri: {redirect_uri}")
            self.log_message(f"  - response_type: {response_type}")

            # Validate parameters
            if not client_id:
                self.send_error(400, "Missing client_id parameter")
                return

            if not redirect_uri:
                self.send_error(400, "Missing redirect_uri parameter")
                return

            if response_type != "code":
                self.send_error(400, f"Unsupported response_type: {response_type}")
                return

            # Validate client_id
            if client_id != DEFAULT_CLIENT_ID:
                self.log_message(f"ERROR: client_id mismatch!")
                self.log_message(f"  Expected: {DEFAULT_CLIENT_ID}")
                self.log_message(f"  Received: {client_id}")
                self.send_error(401, f"Invalid client_id. Expected: {DEFAULT_CLIENT_ID}")
                return

            # Check if redirect_uri looks correct for Gerrit
            if "/login/" not in redirect_uri:
                self.log_message(f"WARNING: redirect_uri may be incorrect!")
                self.log_message(f"  Expected pattern: http://YOUR_HOST:PORT/login/uac-oauth")
                self.log_message(f"  Received: {redirect_uri}")
                self.log_message(f"  This may cause 404 errors on callback!")

            # For testing, we auto-approve and generate a code
            # In a real OAuth flow, this would show a consent screen
            code = secrets.token_urlsafe(32)
            expires_at = time.time() + 600  # 10 minutes

            authorization_codes[code] = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "expires_at": expires_at
            }

            # Redirect back with authorization code
            redirect_url = f"{redirect_uri}?code={code}"
            if state:
                redirect_url += f"&state={state}"

            self.send_response(302)
            self.send_header("Location", redirect_url)
            self.end_headers()
            self.log_message(f"Authorization granted: code={code[:8]}...")
            self.log_message(f"Redirecting to: {redirect_url[:80]}...")

        except Exception as e:
            self.log_message(f"Error in handle_authorize: {e}")
            self.send_error(500, f"Internal Server Error: {e}")

    def handle_token(self):
        """Handle OAuth token request"""
        try:
            # Parse request body
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            params = parse_qs(body)

            # Also check query string (some clients send it there)
            parsed_path = urlparse(self.path)
            if parsed_path.query:
                query_params = parse_qs(parsed_path.query)
                for key, value in query_params.items():
                    if key not in params:
                        params[key] = value

            grant_type = params.get("grant_type", [None])[0]
            code = params.get("code", [None])[0]
            client_id = params.get("client_id", [None])[0]
            client_secret = params.get("client_secret", [None])[0]
            redirect_uri = params.get("redirect_uri", [None])[0]

            # Validate grant type
            if grant_type != "authorization_code":
                self.send_error(400, f"Unsupported grant_type: {grant_type}")
                return

            # Validate code
            if not code or code not in authorization_codes:
                self.send_error(400, "Invalid or expired authorization code")
                return

            code_data = authorization_codes[code]

            # Check expiration
            if time.time() > code_data["expires_at"]:
                del authorization_codes[code]
                self.send_error(400, "Authorization code expired")
                return

            # Validate client credentials
            if client_id != code_data["client_id"]:
                self.send_error(401, "Invalid client_id")
                return

            # For testing, we accept any client_secret, but in production this should be validated
            if client_secret and client_secret != DEFAULT_CLIENT_SECRET:
                self.log_message(f"Warning: client_secret mismatch (testing mode)")

            # Validate redirect_uri matches
            if redirect_uri and redirect_uri != code_data["redirect_uri"]:
                self.send_error(400, "redirect_uri mismatch")
                return

            # Generate access token
            access_token = secrets.token_urlsafe(32)
            expires_at = time.time() + 3600  # 1 hour

            access_tokens[access_token] = {
                "client_id": client_id,
                "user_id": DEFAULT_USER["id"],
                "expires_at": expires_at
            }

            # Clean up authorization code
            del authorization_codes[code]

            # Return token response
            token_response = {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid"
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(token_response).encode("utf-8"))
            self.log_message(f"Token issued: token={access_token[:8]}...")

        except Exception as e:
            self.log_message(f"Error in handle_token: {e}")
            self.send_error(500, f"Internal Server Error: {e}")

    def handle_user_info(self):
        """Handle user info request"""
        try:
            # Extract access token from Authorization header
            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                # Try OAuth token in query parameter (for testing)
                parsed_path = urlparse(self.path)
                params = parse_qs(parsed_path.query)
                token = params.get("access_token", [None])[0]
                if not token:
                    self.send_error(401, "Missing or invalid Authorization header")
                    return
            else:
                token = auth_header[7:]  # Remove "Bearer " prefix

            # Validate token
            if token not in access_tokens:
                self.send_error(401, "Invalid access token")
                return

            token_data = access_tokens[token]

            # Check expiration
            if time.time() > token_data["expires_at"]:
                del access_tokens[token]
                self.send_error(401, "Access token expired")
                return

            # Return user info
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(DEFAULT_USER).encode("utf-8"))
            self.log_message(f"User info returned for token={token[:8]}...")

        except Exception as e:
            self.log_message(f"Error in handle_user_info: {e}")
            self.send_error(500, f"Internal Server Error: {e}")

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Fake UAC OAuth Provider for testing Gerrit OAuth plugin"
    )
    parser.add_argument(
        "--port", type=int, default=8000,
        help="Port to listen on (default: 8000)"
    )
    parser.add_argument(
        "--host", type=str, default="localhost",
        help="Host to bind to (default: localhost)"
    )
    args = parser.parse_args()

    server_address = (args.host, args.port)
    httpd = HTTPServer(server_address, OAuthRequestHandler)

    print(f"Fake UAC OAuth Provider starting...")
    print(f"Listening on http://{args.host}:{args.port}")
    print(f"\nOAuth Configuration:")
    print(f"  - Client ID: {DEFAULT_CLIENT_ID}")
    print(f"  - Client Secret: {DEFAULT_CLIENT_SECRET[:8]}..." if len(DEFAULT_CLIENT_SECRET) > 8 else f"  - Client Secret: {DEFAULT_CLIENT_SECRET}")
    print(f"\nEndpoints:")
    print(f"  - Authorization: http://{args.host}:{args.port}/oauth/authorize")
    print(f"  - Token: http://{args.host}:{args.port}/oauth/token")
    print(f"  - User Info: http://{args.host}:{args.port}/api/user")
    print(f"\nTest User:")
    print(f"  - ID: {DEFAULT_USER['id']}")
    print(f"  - Email: {DEFAULT_USER['email']}")
    print(f"  - Login: {DEFAULT_USER['login']}")
    print(f"  - Name: {DEFAULT_USER['name']}")
    print(f"\nNote: Ensure gerrit.config matches these client credentials")
    print(f"\n" + "="*70)
    print(f"IMPORTANT: Gerrit OAuth Callback Configuration")
    print(f"="*70)
    print(f"For UAC OAuth provider, Gerrit will use this callback URL:")
    print(f"  http://YOUR_GERRIT_HOST:PORT/login/uac-oauth")
    print(f"\nExample: If Gerrit runs on http://127.0.0.1:8080, callback is:")
    print(f"  http://127.0.0.1:8080/login/uac-oauth")
    print(f"\nIf you see 404 errors, check that:")
    print(f"  1. gerrit.config has: [plugin \"gerrit-oauth-provider-uac-oauth\"]")
    print(f"  2. The provider name after 'gerrit-oauth-provider-' is 'uac-oauth'")
    print(f"  3. Gerrit is properly configured and restarted")
    print(f"="*70)
    print(f"\nPress Ctrl+C to stop the server\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.shutdown()


if __name__ == "__main__":
    main()

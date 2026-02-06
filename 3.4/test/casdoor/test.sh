#!/bin/bash

# Test script for Casdoor OAuth Provider
# This script tests OAuth authentication using Client Credentials Grant flow
# Reference: https://www.casdoor.org/docs/basic/public-api#obtaining-access-tokens-with-client-credentials

set -e

# Configuration
CASDOOR_HOST="${CASDOOR_HOST:-localhost:8000}"
# You can set either:
# - CASDOOR_URL="http(s)://host:port" (preferred for remote / https)
# - CASDOOR_HOST="host:port" OR CASDOOR_HOST="http(s)://host:port"
CASDOOR_URL="${CASDOOR_URL:-}"
CASDOOR_CLIENT_ID="${CASDOOR_CLIENT_ID:-}"
CASDOOR_CLIENT_SECRET="${CASDOOR_CLIENT_SECRET:-}"

# Provider/OAuth API testing (reads URLs from Casdoor provider, or override via env)
CASDOOR_PROVIDER_ID="${CASDOOR_PROVIDER_ID:-admin/provider_oauth_custom}"
OAUTH_AUTH_URL="${OAUTH_AUTH_URL:-}"
OAUTH_TOKEN_URL="${OAUTH_TOKEN_URL:-}"
OAUTH_USERINFO_URL="${OAUTH_USERINFO_URL:-}"
OAUTH_PROVIDER_CLIENT_ID="${OAUTH_PROVIDER_CLIENT_ID:-}"
OAUTH_PROVIDER_CLIENT_SECRET="${OAUTH_PROVIDER_CLIENT_SECRET:-}"
OAUTH_REDIRECT_URI="${OAUTH_REDIRECT_URI:-http://localhost/callback}"
OAUTH_SCOPE="${OAUTH_SCOPE:-openid profile email}"
OAUTH_STATE="${OAUTH_STATE:-test-state}"

# Normalize base URL to avoid "http://http://..." mistakes.
RAW_CASDOOR_BASE="${CASDOOR_URL:-$CASDOOR_HOST}"
if [[ "$RAW_CASDOOR_BASE" =~ ^https?:// ]]; then
    CASDOOR_URL="$RAW_CASDOOR_BASE"
else
    CASDOOR_URL="http://${RAW_CASDOOR_BASE}"
fi
CASDOOR_URL="${CASDOOR_URL%/}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Curl defaults
CURL_CONNECT_TIMEOUT_SECONDS="${CURL_CONNECT_TIMEOUT_SECONDS:-5}"
CURL_MAX_TIME_SECONDS="${CURL_MAX_TIME_SECONDS:-30}"
CURL_OPTS=(--connect-timeout "$CURL_CONNECT_TIMEOUT_SECONDS" --max-time "$CURL_MAX_TIME_SECONDS" --silent --show-error)

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1" >&2
}

# Check if required tools are available
check_dependencies() {
    log_step "Checking dependencies..."

    if ! command -v curl &> /dev/null; then
        log_error "curl is not installed. Please install curl first."
        exit 1
    fi

    if ! command -v jq &> /dev/null; then
        log_warn "jq is not installed. JSON parsing will be limited."
        JQ_AVAILABLE=false
    else
        JQ_AVAILABLE=true
    fi

    log_info "Dependencies check passed"
}

urlencode() {
    local raw="$1"
    if command -v python3 &> /dev/null; then
        python3 - <<'PY'
import os, sys, urllib.parse
print(urllib.parse.quote(sys.stdin.read().strip(), safe=""))
PY
    else
        # Best effort: no encoding (works for most simple values)
        printf '%s' "$raw"
    fi
}

curl_http_code() {
    # Prints only HTTP code to stdout
    # Usage: curl_http_code METHOD URL [extra curl args...]
    local method="$1"; shift
    local url="$1"; shift
    curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" -X "$method" "$@" "$url"
}

casdoor_api_get() {
    # GET a Casdoor API path with clientId/clientSecret auth (if needed).
    # Usage: casdoor_api_get "/api/get-provider" "id=xxx"
    local path="$1"
    local query="${2:-}"
    local sep='?'
    [[ "$path" == *\?* ]] && sep='&'
    local url="${CASDOOR_URL}${path}${sep}${query}"
    if [[ -n "$query" ]]; then
        url="${url}&clientId=$(urlencode "$CASDOOR_CLIENT_ID")&clientSecret=$(urlencode "$CASDOOR_CLIENT_SECRET")"
    else
        url="${url}clientId=$(urlencode "$CASDOOR_CLIENT_ID")&clientSecret=$(urlencode "$CASDOOR_CLIENT_SECRET")"
    fi
    curl "${CURL_OPTS[@]}" "$url"
}

# Check if Casdoor is accessible
check_casdoor_health() {
    log_step "Checking Casdoor health..."

    local health_url="${CASDOOR_URL}/api/get-global-providers"
    local response

    if response=$(curl "${CURL_OPTS[@]}" "$health_url" 2>&1); then
        log_info "Casdoor is accessible at ${CASDOOR_URL}"
        return 0
    else
        log_error "Cannot connect to Casdoor at ${CASDOOR_URL}"
        log_error "Response: $response"
        log_error "Please ensure Casdoor is running and accessible"
        return 1
    fi
}

# Validate configuration
validate_config() {
    log_step "Validating configuration..."

    if [ -z "$CASDOOR_CLIENT_ID" ]; then
        log_error "CASDOOR_CLIENT_ID is not set"
        log_error "Please set it as an environment variable or export it:"
        log_error "  export CASDOOR_CLIENT_ID='your-client-id'"
        return 1
    fi

    if [ -z "$CASDOOR_CLIENT_SECRET" ]; then
        log_error "CASDOOR_CLIENT_SECRET is not set"
        log_error "Please set it as an environment variable or export it:"
        log_error "  export CASDOOR_CLIENT_SECRET='your-client-secret'"
        return 1
    fi

    log_info "Configuration validated"
    log_info "  Base URL: ${CASDOOR_URL}"
    log_info "  Client ID: ${CASDOOR_CLIENT_ID:0:10}..."
    return 0
}

get_provider_oauth_urls() {
    # Populates OAUTH_AUTH_URL / OAUTH_TOKEN_URL / OAUTH_USERINFO_URL and optional provider client credentials
    # from Casdoor provider config.
    if [ "$JQ_AVAILABLE" != true ]; then
        log_warn "jq not available; cannot parse provider config automatically."
        return 1
    fi

    log_step "Fetching Casdoor provider config: ${CASDOOR_PROVIDER_ID}"

    local enc_id
    enc_id="$(urlencode "$CASDOOR_PROVIDER_ID")"

    local response=""
    local endpoints=(
        "/api/get-provider?id=${enc_id}"
        "/api/get-provider?providerId=${enc_id}"
        "/api/get-provider?owner=$(urlencode "${CASDOOR_PROVIDER_ID%/*}")&name=$(urlencode "${CASDOOR_PROVIDER_ID#*/}")"
    )

    for ep in "${endpoints[@]}"; do
        response="$(casdoor_api_get "$ep" "")" || true
        local status
        status="$(echo "$response" | jq -r '.status // empty' 2>/dev/null || true)"
        if [ "$status" = "ok" ]; then
            break
        fi
        response=""
    done

    if [ -z "$response" ]; then
        log_error "Could not fetch provider config via Casdoor API."
        return 1
    fi

    local data
    data="$(echo "$response" | jq -c '.data // empty' 2>/dev/null || true)"
    if [ -z "$data" ] || [ "$data" = "null" ]; then
        log_error "Provider response missing .data"
        echo "$response" | jq '.' 2>/dev/null || true
        return 1
    fi

    # Common field names seen in OAuth provider configs
    local auth_url token_url userinfo_url
    auth_url="$(echo "$data" | jq -r '.authorizationUrl // .authUrl // .authUrl2 // .authUrl3 // empty')"
    token_url="$(echo "$data" | jq -r '.tokenUrl // .tokenURL // empty')"
    userinfo_url="$(echo "$data" | jq -r '.userinfoUrl // .userInfoUrl // .userInfoURL // empty')"

    if [ -n "$auth_url" ]; then OAUTH_AUTH_URL="$auth_url"; fi
    if [ -n "$token_url" ]; then OAUTH_TOKEN_URL="$token_url"; fi
    if [ -n "$userinfo_url" ]; then OAUTH_USERINFO_URL="$userinfo_url"; fi

    # Provider client credentials (optional)
    if [ -z "$OAUTH_PROVIDER_CLIENT_ID" ]; then
        OAUTH_PROVIDER_CLIENT_ID="$(echo "$data" | jq -r '.clientId // .clientID // empty' | tr -d '\r\n')"
    fi
    if [ -z "$OAUTH_PROVIDER_CLIENT_SECRET" ]; then
        OAUTH_PROVIDER_CLIENT_SECRET="$(echo "$data" | jq -r '.clientSecret // .clientSecretValue // .clientSecretText // empty' | tr -d '\r\n')"
    fi

    log_info "Provider OAuth URLs:"
    log_info "  auth:     ${OAUTH_AUTH_URL:-<empty>}"
    log_info "  token:    ${OAUTH_TOKEN_URL:-<empty>}"
    log_info "  userinfo: ${OAUTH_USERINFO_URL:-<empty>}"

    return 0
}

test_oauth_provider_endpoints() {
    log_step "Testing OAuth endpoints from provider (${CASDOOR_PROVIDER_ID})..."

    # If URLs not provided, try to fetch from provider config.
    if [ -z "$OAUTH_AUTH_URL" ] || [ -z "$OAUTH_TOKEN_URL" ] || [ -z "$OAUTH_USERINFO_URL" ]; then
        get_provider_oauth_urls || true
    fi

    if [ -z "$OAUTH_AUTH_URL" ] && [ -z "$OAUTH_TOKEN_URL" ] && [ -z "$OAUTH_USERINFO_URL" ]; then
        log_warn "No OAuth URLs available (set OAUTH_AUTH_URL/OAUTH_TOKEN_URL/OAUTH_USERINFO_URL or install jq). Skipping provider OAuth API tests."
        return 0
    fi

    # 4a) Auth URL reachability (usually 302 to login page)
    if [ -n "$OAUTH_AUTH_URL" ]; then
        log_info "--- Test 4a: Provider auth URL reachability ---"
        local sep='?'
        [[ "$OAUTH_AUTH_URL" == *\?* ]] && sep='&'
        local auth_req="${OAUTH_AUTH_URL}${sep}response_type=code&client_id=$(urlencode "${OAUTH_PROVIDER_CLIENT_ID:-$CASDOOR_CLIENT_ID}")&redirect_uri=$(urlencode "$OAUTH_REDIRECT_URI")&scope=$(urlencode "$OAUTH_SCOPE")&state=$(urlencode "$OAUTH_STATE")"
        local code
        code="$(curl_http_code GET "$auth_req")" || true
        if [[ "$code" =~ ^(200|30[1278]|401)$ ]]; then
            log_info "Auth URL responded with HTTP ${code}"
        else
            log_error "Auth URL unexpected HTTP ${code}"
        fi
        echo ""
    fi

    # 4b) Token URL (try client_credentials, if provider supports it)
    local provider_token=""
    if [ -n "$OAUTH_TOKEN_URL" ]; then
        log_info "--- Test 4b: Provider token URL (client_credentials) ---"

        if [ -z "$OAUTH_PROVIDER_CLIENT_ID" ] || [ -z "$OAUTH_PROVIDER_CLIENT_SECRET" ]; then
            log_warn "Provider client_id/client_secret not available (set OAUTH_PROVIDER_CLIENT_ID/OAUTH_PROVIDER_CLIENT_SECRET to actually request a token)."
        else
            local resp
            # Try form-encoded parameters first
            resp="$(curl "${CURL_OPTS[@]}" \
                -X POST \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "grant_type=client_credentials&client_id=$(urlencode "$OAUTH_PROVIDER_CLIENT_ID")&client_secret=$(urlencode "$OAUTH_PROVIDER_CLIENT_SECRET")" \
                "$OAUTH_TOKEN_URL" 2>&1)" || true

            if echo "$resp" | grep -q '"access_token"'; then
                log_info "Token URL returned an access_token"
                if [ "$JQ_AVAILABLE" = true ]; then
                    provider_token="$(echo "$resp" | jq -r '.access_token // empty' | tr -d '\r\n')"
                fi
            else
                # Try Basic auth + grant_type only
                resp="$(curl "${CURL_OPTS[@]}" \
                    -X POST \
                    -u "${OAUTH_PROVIDER_CLIENT_ID}:${OAUTH_PROVIDER_CLIENT_SECRET}" \
                    -H "Content-Type: application/x-www-form-urlencoded" \
                    -d "grant_type=client_credentials" \
                    "$OAUTH_TOKEN_URL" 2>&1)" || true
                if echo "$resp" | grep -q '"access_token"'; then
                    log_info "Token URL returned an access_token (Basic auth)"
                    if [ "$JQ_AVAILABLE" = true ]; then
                        provider_token="$(echo "$resp" | jq -r '.access_token // empty' | tr -d '\r\n')"
                    fi
                else
                    # Classify common OAuth errors to avoid confusing WARNs.
                    if [ "$JQ_AVAILABLE" = true ] && echo "$resp" | jq -e . >/dev/null 2>&1; then
                        local err
                        local err_desc
                        err="$(echo "$resp" | jq -r '.error // empty')"
                        err_desc="$(echo "$resp" | jq -r '.error_description // empty')"

                        if [ "$err" = "invalid_client" ]; then
                            log_error "Provider token request failed: invalid_client"
                            if [ -n "$err_desc" ]; then
                                log_error "Reason: ${err_desc}"
                            fi
                            log_error "Fix: set correct OAUTH_PROVIDER_CLIENT_ID/OAUTH_PROVIDER_CLIENT_SECRET for the upstream provider."
                        elif [ "$err" = "unsupported_grant_type" ]; then
                            log_info "Provider does not support client_credentials; skipping provider token/userinfo checks."
                        else
                            log_error "Provider token request did not return access_token."
                            if [ -n "$err" ]; then
                                log_error "error=${err}"
                            fi
                            if [ -n "$err_desc" ]; then
                                log_error "error_description=${err_desc}"
                            fi
                            log_info "Raw response:"
                            echo "$resp" >&2
                        fi
                    else
                        log_error "Provider token request did not return access_token. Raw response:"
                        echo "$resp" >&2
                    fi
                fi
            fi
        fi

        echo ""
    fi

    # 4c) Userinfo URL (if we got a provider token)
    if [ -n "$OAUTH_USERINFO_URL" ]; then
        log_info "--- Test 4c: Provider userinfo URL ---"
        if [ -z "$provider_token" ]; then
            log_info "Skipped userinfo call (no provider access token available)."
        else
            local code
            code="$(curl_http_code GET "$OAUTH_USERINFO_URL" -H "Authorization: Bearer ${provider_token}")" || true
            if [[ "$code" =~ ^(200|30[1278])$ ]]; then
                log_info "Userinfo URL responded with HTTP ${code}"
            else
                log_error "Userinfo URL unexpected HTTP ${code}"
            fi
        fi
        echo ""
    fi

    return 0
}

# Obtain access token using Client Credentials Grant
obtain_access_token() {
    log_step "Obtaining access token using Client Credentials Grant..."

    local token_url="${CASDOOR_URL}/api/login/oauth/access_token"
    local response

    log_info "Requesting token from: ${token_url}"

    response=$(curl "${CURL_OPTS[@]}" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{
            \"grant_type\": \"client_credentials\",
            \"client_id\": \"${CASDOOR_CLIENT_ID}\",
            \"client_secret\": \"${CASDOOR_CLIENT_SECRET}\"
        }" \
        "$token_url" 2>&1)

    if [ $? -ne 0 ]; then
        log_error "Failed to obtain access token"
        log_error "Response: $response"
        return 1
    fi

    if [ "$JQ_AVAILABLE" = true ]; then
        # Parse JSON response
        local access_token
        access_token="$(echo "$response" | jq -r '.access_token // empty' | tr -d '\r\n')"
        local token_type=$(echo "$response" | jq -r '.token_type // empty')
        local expires_in=$(echo "$response" | jq -r '.expires_in // empty')
        local scope=$(echo "$response" | jq -r '.scope // empty')

        if [ -z "$access_token" ] || [ "$access_token" = "null" ]; then
            log_error "Failed to obtain access token. Response:"
            echo "$response" | jq '.' 2>/dev/null || echo "$response"
            return 1
        fi

        log_info "Access token obtained successfully"
        log_info "  Token type: ${token_type}"
        log_info "  Expires in: ${expires_in} seconds"
        log_info "  Scope: ${scope}"
        log_info "  Token: ${access_token:0:20}..."

        # IMPORTANT: only print the raw token to stdout (callers capture it).
        printf '%s' "$access_token"
        return 0
    else
        # Fallback: try to extract token manually
        if echo "$response" | grep -q "access_token"; then
            log_info "Access token obtained (JSON parsing not available)"
            # Best effort: emit the full response (cannot parse without jq).
            printf '%s' "$response"
            return 0
        else
            log_error "Failed to obtain access token. Response:"
            echo "$response"
            return 1
        fi
    fi
}

# Test API call with access token (Bearer token method)
test_api_with_bearer_token() {
    local access_token="$1"
    log_step "Testing API call with Bearer token authentication..."

    local api_url="${CASDOOR_URL}/api/get-global-providers"
    local response

    response=$(curl "${CURL_OPTS[@]}" \
        -H "Authorization: Bearer ${access_token}" \
        "$api_url" 2>&1)

    if [ $? -ne 0 ]; then
        log_error "API call failed"
        log_error "Response: $response"
        return 1
    fi

    if [ "$JQ_AVAILABLE" = true ]; then
        local status=$(echo "$response" | jq -r '.status // empty')
        if [ "$status" = "ok" ]; then
            log_info "API call successful with Bearer token"
            return 0
        else
            log_error "API call returned error status: $status"
            echo "$response" | jq '.' 2>/dev/null || echo "$response"
            return 1
        fi
    else
        if echo "$response" | grep -q "status"; then
            log_info "API call successful with Bearer token"
            return 0
        else
            log_error "API call may have failed. Response:"
            echo "$response"
            return 1
        fi
    fi
}

# Test API call with access token (GET parameter method)
test_api_with_get_param() {
    local access_token="$1"
    log_step "Testing API call with access_token GET parameter..."

    local api_url="${CASDOOR_URL}/api/get-global-providers?access_token=${access_token}"
    local response

    response=$(curl "${CURL_OPTS[@]}" "$api_url" 2>&1)

    if [ $? -ne 0 ]; then
        log_error "API call failed"
        log_error "Response: $response"
        return 1
    fi

    if [ "$JQ_AVAILABLE" = true ]; then
        local status=$(echo "$response" | jq -r '.status // empty')
        if [ "$status" = "ok" ]; then
            log_info "API call successful with GET parameter"
            return 0
        else
            log_error "API call returned error status: $status"
            echo "$response" | jq '.' 2>/dev/null || echo "$response"
            return 1
        fi
    else
        if echo "$response" | grep -q "status"; then
            log_info "API call successful with GET parameter"
            return 0
        else
            log_error "API call may have failed. Response:"
            echo "$response"
            return 1
        fi
    fi
}

# Test API call with client credentials (direct method)
test_api_with_client_credentials() {
    log_step "Testing API call with client credentials (direct method)..."

    local api_url="${CASDOOR_URL}/api/get-global-providers?clientId=${CASDOOR_CLIENT_ID}&clientSecret=${CASDOOR_CLIENT_SECRET}"
    local response

    response=$(curl "${CURL_OPTS[@]}" "$api_url" 2>&1)

    if [ $? -ne 0 ]; then
        log_error "API call failed"
        log_error "Response: $response"
        return 1
    fi

    if [ "$JQ_AVAILABLE" = true ]; then
        local status=$(echo "$response" | jq -r '.status // empty')
        if [ "$status" = "ok" ]; then
            log_info "API call successful with client credentials"
            return 0
        else
            log_error "API call returned error status: $status"
            echo "$response" | jq '.' 2>/dev/null || echo "$response"
            return 1
        fi
    else
        if echo "$response" | grep -q "status"; then
            log_info "API call successful with client credentials"
            return 0
        else
            log_error "API call may have failed. Response:"
            echo "$response"
            return 1
        fi
    fi
}

# Test API call with Basic Authentication
test_api_with_basic_auth() {
    log_step "Testing API call with Basic Authentication..."

    # Base64 encode client_id:client_secret
    local credentials="${CASDOOR_CLIENT_ID}:${CASDOOR_CLIENT_SECRET}"
    local encoded_credentials
    if command -v base64 &> /dev/null; then
        # Strip trailing newline from base64 output to keep header valid.
        encoded_credentials=$(printf '%s' "$credentials" | base64 | tr -d '\r\n')
    elif command -v openssl &> /dev/null; then
        encoded_credentials=$(printf '%s' "$credentials" | openssl base64 | tr -d '\r\n')
    else
        log_warn "base64/openssl not available, skipping Basic Auth test"
        return 0
    fi

    local api_url="${CASDOOR_URL}/api/get-global-providers"
    local response

    response=$(curl "${CURL_OPTS[@]}" \
        -H "Authorization: Basic ${encoded_credentials}" \
        "$api_url" 2>&1)

    if [ $? -ne 0 ]; then
        log_error "API call failed"
        log_error "Response: $response"
        return 1
    fi

    if [ "$JQ_AVAILABLE" = true ]; then
        local status=$(echo "$response" | jq -r '.status // empty')
        if [ "$status" = "ok" ]; then
            log_info "API call successful with Basic Authentication"
            return 0
        else
            log_error "API call returned error status: $status"
            echo "$response" | jq '.' 2>/dev/null || echo "$response"
            return 1
        fi
    else
        if echo "$response" | grep -q "status"; then
            log_info "API call successful with Basic Authentication"
            return 0
        else
            log_error "API call may have failed. Response:"
            echo "$response"
            return 1
        fi
    fi
}

# Main test function
main() {
    log_info "=========================================="
    log_info "Casdoor OAuth Provider Test"
    log_info "=========================================="
    echo ""

    # Check dependencies
    check_dependencies
    echo ""

    # Check Casdoor health
    if ! check_casdoor_health; then
        exit 1
    fi
    echo ""

    # Validate configuration
    if ! validate_config; then
        exit 1
    fi
    echo ""

    # Test 1: Direct client credentials method
    log_info "--- Test 1: Direct Client Credentials ---"
    if test_api_with_client_credentials; then
        log_info "✓ Test 1 passed"
    else
        log_error "✗ Test 1 failed"
    fi
    echo ""

    # Test 2: Basic Authentication
    log_info "--- Test 2: Basic Authentication ---"
    if test_api_with_basic_auth; then
        log_info "✓ Test 2 passed"
    else
        log_error "✗ Test 2 failed"
    fi
    echo ""

    # Test 3: Client Credentials Grant (OAuth 2.0)
    log_info "--- Test 3: Client Credentials Grant (OAuth 2.0) ---"
    local access_token
    if access_token=$(obtain_access_token); then
        log_info "✓ Token obtained"
        echo ""

        # Test 3a: Bearer token
        log_info "--- Test 3a: API call with Bearer token ---"
        if test_api_with_bearer_token "$access_token"; then
            log_info "✓ Test 3a passed"
        else
            log_error "✗ Test 3a failed"
        fi
        echo ""

        # Test 3b: GET parameter
        log_info "--- Test 3b: API call with GET parameter ---"
        if test_api_with_get_param "$access_token"; then
            log_info "✓ Test 3b passed"
        else
            log_error "✗ Test 3b failed"
        fi
    else
        log_error "✗ Test 3 failed: Could not obtain access token"
    fi
    echo ""

    # Test 4: OAuth provider endpoint checks (auth/token/userinfo URLs in provider)
    log_info "--- Test 4: Provider OAuth API endpoints ---"
    if test_oauth_provider_endpoints; then
        log_info "✓ Test 4 completed"
    else
        log_error "✗ Test 4 failed"
    fi
    echo ""

    log_info "=========================================="
    log_info "Test completed"
    log_info "=========================================="
}

# Run main function
main

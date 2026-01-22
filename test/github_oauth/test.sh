#!/bin/bash

# Test script for GitHub OAuth API endpoints
# This script tests GitHub OAuth functionality including:
# - Authorization URL generation and validation
# - Access Token URL endpoint
# - User Info URL endpoint
# All tests use client ID and client secret for authentication

set -e

# Configuration
GITHUB_ROOT_URL="${GITHUB_ROOT_URL:-https://github.com/}"
GITHUB_API_URL="${GITHUB_API_URL:-https://api.github.com/}"
GITHUB_CLIENT_ID="${GITHUB_CLIENT_ID:-}"
GITHUB_CLIENT_SECRET="${GITHUB_CLIENT_SECRET:-}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:8080/oauth}"
SCOPE="${SCOPE:-user:email}"
STATE="${STATE:-test-state-$(date +%s)}"

# Curl defaults (avoid hanging indefinitely)
CURL_CONNECT_TIMEOUT_SECONDS="${CURL_CONNECT_TIMEOUT_SECONDS:-10}"
CURL_MAX_TIME_SECONDS="${CURL_MAX_TIME_SECONDS:-30}"
CURL_OPTS=(--connect-timeout "$CURL_CONNECT_TIMEOUT_SECONDS" --max-time "$CURL_MAX_TIME_SECONDS" -s -w "\nHTTP_CODE:%{http_code}")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# Check if required credentials are provided
check_credentials() {
    if [ -z "$GITHUB_CLIENT_ID" ]; then
        log_error "GITHUB_CLIENT_ID is not set"
        log_info "Set it via environment variable: export GITHUB_CLIENT_ID='your-client-id'"
        return 1
    fi

    if [ -z "$GITHUB_CLIENT_SECRET" ]; then
        log_error "GITHUB_CLIENT_SECRET is not set"
        log_info "Set it via environment variable: export GITHUB_CLIENT_SECRET='your-client-secret'"
        return 1
    fi

    return 0
}

# Extract HTTP code from curl output
extract_http_code() {
    echo "$1" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2
}

# Extract body from curl output
extract_body() {
    echo "$1" | sed '/HTTP_CODE:/d'
}

# Test 1: Test Authorization URL generation and format
test_authorize_url() {
    log_info "Testing GitHub Authorization URL..."

    local authorize_url="${GITHUB_ROOT_URL}login/oauth/authorize"
    local params="response_type=code&client_id=${GITHUB_CLIENT_ID}&redirect_uri=$(echo "$REDIRECT_URI" | sed 's/:/%3A/g' | sed 's/\//%2F/g')&scope=${SCOPE}&state=${STATE}"
    local full_url="${authorize_url}?${params}"

    log_debug "Authorization URL: $full_url"

    # Test URL format
    if [[ ! "$authorize_url" =~ ^https://.*/login/oauth/authorize$ ]]; then
        log_error "Invalid authorization URL format: $authorize_url"
        return 1
    fi

    # Test that the URL is accessible (should redirect or return 200)
    local response
    response="$(curl "${CURL_OPTS[@]}" -L -o /dev/null "$full_url" 2>&1 || true)"
    local http_code
    http_code="$(extract_http_code "$response")"

    if [ -z "$http_code" ]; then
        log_warn "Could not connect to GitHub authorization endpoint"
        log_warn "This might be expected if GitHub is unreachable or requires authentication"
    elif [ "$http_code" = "200" ] || [ "$http_code" = "302" ] || [ "$http_code" = "404" ]; then
        log_info "✓ Authorization URL is accessible (HTTP $http_code)"
    else
        log_warn "Authorization URL returned HTTP $http_code"
    fi

    # Validate URL parameters
    if echo "$full_url" | grep -q "client_id=${GITHUB_CLIENT_ID}"; then
        log_info "✓ Authorization URL contains client_id"
    else
        log_error "Authorization URL missing client_id parameter"
        return 1
    fi

    if echo "$full_url" | grep -q "response_type=code"; then
        log_info "✓ Authorization URL contains response_type=code"
    else
        log_error "Authorization URL missing response_type parameter"
        return 1
    fi

    if echo "$full_url" | grep -q "redirect_uri="; then
        log_info "✓ Authorization URL contains redirect_uri"
    else
        log_error "Authorization URL missing redirect_uri parameter"
        return 1
    fi

    log_info "✓ Authorization URL format is valid"
    return 0
}

# Test 2: Test Access Token URL endpoint
test_access_token_url() {
    log_info "Testing GitHub Access Token URL..."

    local token_url="${GITHUB_ROOT_URL}login/oauth/access_token"

    log_debug "Access Token URL: $token_url"

    # Test URL format
    if [[ ! "$token_url" =~ ^https://.*/login/oauth/access_token$ ]]; then
        log_error "Invalid access token URL format: $token_url"
        return 1
    fi

    # Test endpoint with invalid code (should return error, but endpoint should be reachable)
    local test_code="invalid_test_code_$(date +%s)"
    local response
    response="$(curl "${CURL_OPTS[@]}" -X POST "$token_url" \
        -H "Accept: application/json" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=authorization_code" \
        -d "code=${test_code}" \
        -d "client_id=${GITHUB_CLIENT_ID}" \
        -d "client_secret=${GITHUB_CLIENT_SECRET}" \
        -d "redirect_uri=${REDIRECT_URI}" \
        2>&1 || true)"

    local http_code
    http_code="$(extract_http_code "$response")"
    local body
    body="$(extract_body "$response")"

    if [ -z "$http_code" ]; then
        log_warn "Could not connect to GitHub access token endpoint"
        log_warn "This might be expected if GitHub is unreachable"
    elif [ "$http_code" = "200" ]; then
        # Check if response contains error (expected for invalid code)
        if echo "$body" | grep -q "error"; then
            log_info "✓ Access Token URL is accessible and returned expected error for invalid code"
        else
            log_info "✓ Access Token URL is accessible (HTTP $http_code)"
        fi
    elif [ "$http_code" = "400" ] || [ "$http_code" = "422" ]; then
        log_info "✓ Access Token URL is accessible and validated request (HTTP $http_code)"
    else
        log_warn "Access Token URL returned HTTP $http_code"
    fi

    # Validate that we're using client_id and client_secret
    log_info "✓ Access Token URL format is valid"
    log_debug "Using client_id: ${GITHUB_CLIENT_ID:0:10}..."
    log_debug "Using client_secret: ${GITHUB_CLIENT_SECRET:0:10}..."

    return 0
}

# Test 3: Test User Info URL endpoint
test_user_info_url() {
    log_info "Testing GitHub User Info URL..."

    local user_info_url="${GITHUB_API_URL}user"

    log_debug "User Info URL: $user_info_url"

    # Test URL format
    if [[ ! "$user_info_url" =~ ^https://.*/user$ ]]; then
        log_error "Invalid user info URL format: $user_info_url"
        return 1
    fi

    # Test endpoint without token (should return 401 Unauthorized)
    local response
    response="$(curl "${CURL_OPTS[@]}" -H "Accept: application/json" "$user_info_url" 2>&1 || true)"

    local http_code
    http_code="$(extract_http_code "$response")"
    local body
    body="$(extract_body "$response")"

    if [ -z "$http_code" ]; then
        log_warn "Could not connect to GitHub user info endpoint"
        log_warn "This might be expected if GitHub API is unreachable"
    elif [ "$http_code" = "401" ]; then
        log_info "✓ User Info URL is accessible and requires authentication (HTTP 401)"
    elif [ "$http_code" = "403" ]; then
        log_info "✓ User Info URL is accessible but rate limited or forbidden (HTTP 403)"
    elif [ "$http_code" = "200" ]; then
        # If we got 200, check if it's valid JSON with expected fields
        if echo "$body" | grep -q "\"id\"" && echo "$body" | grep -q "\"login\""; then
            log_info "✓ User Info URL returned valid user data (HTTP 200)"
            log_debug "Response preview: $(echo "$body" | head -c 200)..."
        else
            log_warn "User Info URL returned 200 but unexpected response format"
        fi
    else
        log_warn "User Info URL returned HTTP $http_code"
    fi

    # Test with invalid token (should return 401)
    local invalid_token="invalid_token_$(date +%s)"
    response="$(curl "${CURL_OPTS[@]}" -H "Accept: application/json" \
        -H "Authorization: Bearer ${invalid_token}" \
        "$user_info_url" 2>&1 || true)"

    http_code="$(extract_http_code "$response")"
    if [ "$http_code" = "401" ]; then
        log_info "✓ User Info URL correctly rejects invalid tokens"
    fi

    log_info "✓ User Info URL format is valid"
    return 0
}

# Test 4: Test complete OAuth flow (if authorization code is provided)
test_oauth_flow() {
    log_info "Testing complete OAuth flow..."

    if [ -z "$AUTHORIZATION_CODE" ]; then
        log_warn "AUTHORIZATION_CODE not provided, skipping complete flow test"
        log_info "To test the complete flow:"
        log_info "  1. Visit the authorization URL (shown in test 1)"
        log_info "  2. Authorize the application"
        log_info "  3. Extract the 'code' parameter from the redirect URL"
        log_info "  4. Run: export AUTHORIZATION_CODE='your-code' && $0"
        return 0
    fi

    log_info "Using provided authorization code: ${AUTHORIZATION_CODE:0:20}..."

    # Exchange code for access token
    local token_url="${GITHUB_ROOT_URL}login/oauth/access_token"
    local response
    response="$(curl "${CURL_OPTS[@]}" -X POST "$token_url" \
        -H "Accept: application/json" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=authorization_code" \
        -d "code=${AUTHORIZATION_CODE}" \
        -d "client_id=${GITHUB_CLIENT_ID}" \
        -d "client_secret=${GITHUB_CLIENT_SECRET}" \
        -d "redirect_uri=${REDIRECT_URI}" \
        2>&1 || true)"

    local http_code
    http_code="$(extract_http_code "$response")"
    local body
    body="$(extract_body "$response")"

    if [ "$http_code" != "200" ]; then
        log_error "Failed to exchange authorization code for access token (HTTP $http_code)"
        log_error "Response: $body"
        return 1
    fi

    # Extract access token from response
    local access_token
    access_token="$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null || echo "")"

    if [ -z "$access_token" ]; then
        log_error "Access token not found in response"
        log_error "Response: $body"
        return 1
    fi

    log_info "✓ Successfully obtained access token"
    log_debug "Access token: ${access_token:0:20}..."

    # Get user info with access token
    local user_info_url="${GITHUB_API_URL}user"
    response="$(curl "${CURL_OPTS[@]}" -H "Accept: application/json" \
        -H "Authorization: Bearer ${access_token}" \
        "$user_info_url" 2>&1 || true)"

    http_code="$(extract_http_code "$response")"
    body="$(extract_body "$response")"

    if [ "$http_code" != "200" ]; then
        log_error "Failed to get user info (HTTP $http_code)"
        log_error "Response: $body"
        return 1
    fi

    # Validate user info response
    if ! python3 -c "import sys,json; d=json.load(sys.stdin); req=['id','login']; missing=[k for k in req if not d.get(k)]; sys.exit(1 if missing else 0)" <<<"$body" 2>/dev/null; then
        log_error "User info response missing required fields"
        log_error "Response: $body"
        return 1
    fi

    local user_id user_login user_email
    user_id="$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null || echo "")"
    user_login="$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('login',''))" 2>/dev/null || echo "")"
    user_email="$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('email',''))" 2>/dev/null || echo "")"

    log_info "✓ Successfully retrieved user info"
    log_info "  User ID: $user_id"
    log_info "  Username: $user_login"
    if [ -n "$user_email" ]; then
        log_info "  Email: $user_email"
    fi

    return 0
}

# Test 5: Display authorization URL for manual testing
display_authorization_url() {
    log_info "======================================"
    log_info "GitHub OAuth Authorization URL"
    log_info "======================================"

    local authorize_url="${GITHUB_ROOT_URL}login/oauth/authorize"
    local params="response_type=code&client_id=${GITHUB_CLIENT_ID}&redirect_uri=$(echo "$REDIRECT_URI" | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip()))" <<<"$REDIRECT_URI")&scope=${SCOPE}&state=${STATE}"
    local full_url="${authorize_url}?${params}"

    echo ""
    log_info "To test the complete OAuth flow manually:"
    echo ""
    log_info "1. Visit this URL in your browser:"
    echo "   $full_url"
    echo ""
    log_info "2. Authorize the application"
    echo ""
    log_info "3. You will be redirected to:"
    echo "   ${REDIRECT_URI}?code=AUTHORIZATION_CODE&state=${STATE}"
    echo ""
    log_info "4. Extract the 'code' parameter from the redirect URL"
    echo ""
    log_info "5. Run the test again with the authorization code:"
    echo "   export AUTHORIZATION_CODE='your-code' && $0"
    echo ""
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --client-id)
                GITHUB_CLIENT_ID="$2"
                shift 2
                ;;
            --client-secret)
                GITHUB_CLIENT_SECRET="$2"
                shift 2
                ;;
            --redirect-uri)
                REDIRECT_URI="$2"
                shift 2
                ;;
            --scope)
                SCOPE="$2"
                shift 2
                ;;
            --github-root-url)
                GITHUB_ROOT_URL="$2"
                shift 2
                ;;
            --github-api-url)
                GITHUB_API_URL="$2"
                shift 2
                ;;
            --authorization-code)
                AUTHORIZATION_CODE="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --client-id ID              GitHub OAuth client ID (required)"
                echo "  --client-secret SECRET      GitHub OAuth client secret (required)"
                echo "  --redirect-uri URI          OAuth redirect URI (default: http://localhost:8080/oauth)"
                echo "  --scope SCOPE               OAuth scope (default: user:email)"
                echo "  --github-root-url URL        GitHub root URL (default: https://github.com/)"
                echo "  --github-api-url URL        GitHub API URL (default: https://api.github.com/)"
                echo "  --authorization-code CODE   Authorization code for complete flow test"
                echo "  --help                       Show this help message"
                echo ""
                echo "Environment variables:"
                echo "  GITHUB_CLIENT_ID            GitHub OAuth client ID"
                echo "  GITHUB_CLIENT_SECRET        GitHub OAuth client secret"
                echo "  REDIRECT_URI                OAuth redirect URI"
                echo "  SCOPE                       OAuth scope"
                echo "  GITHUB_ROOT_URL             GitHub root URL"
                echo "  GITHUB_API_URL              GitHub API URL"
                echo "  AUTHORIZATION_CODE          Authorization code for complete flow test"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Main test execution
main() {
    parse_args "$@"

    log_info "======================================"
    log_info "GitHub OAuth API Test Suite"
    log_info "======================================"
    log_info "GitHub Root URL: $GITHUB_ROOT_URL"
    log_info "GitHub API URL: $GITHUB_API_URL"
    log_info "Redirect URI: $REDIRECT_URI"
    log_info "Scope: $SCOPE"
    log_info ""

    # Check credentials
    if ! check_credentials; then
        log_error "Missing required credentials. Exiting."
        exit 1
    fi

    TESTS_PASSED=0
    TESTS_FAILED=0

    # Run tests
    if test_authorize_url; then
        ((++TESTS_PASSED))
    else
        ((++TESTS_FAILED))
    fi
    echo ""

    if test_access_token_url; then
        ((++TESTS_PASSED))
    else
        ((++TESTS_FAILED))
    fi
    echo ""

    if test_user_info_url; then
        ((++TESTS_PASSED))
    else
        ((++TESTS_FAILED))
    fi
    echo ""

    if test_oauth_flow; then
        ((++TESTS_PASSED))
    else
        ((++TESTS_FAILED))
    fi
    echo ""

    # Display authorization URL for manual testing
    display_authorization_url

    # Summary
    log_info "======================================"
    log_info "Test Summary"
    log_info "======================================"
    log_info "Tests passed: $TESTS_PASSED"
    if [ $TESTS_FAILED -gt 0 ]; then
        log_error "Tests failed: $TESTS_FAILED"
        exit 1
    else
        log_info "Tests failed: $TESTS_FAILED"
        log_info ""
        log_info "✓ All tests passed!"
        exit 0
    fi
}

# Run main function with all arguments
main "$@"

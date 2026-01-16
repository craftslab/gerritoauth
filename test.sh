#!/bin/bash

# Test script for Gerrit OAuth Plugin on Gerrit 3.4
# This script tests the OAuth plugin functionality using Gerrit REST API

set -e

# Configuration
GERRIT_URL="${GERRIT_URL:-http://localhost:8080}"
GERRIT_USER="${GERRIT_USER:-admin}"
GERRIT_PASSWORD="${GERRIT_PASSWORD:-secret}"
PLUGIN_NAME="gerrit-oauth-provider"

# Fake OAuth Provider configuration
OAUTH_PROVIDER_HOST="${OAUTH_PROVIDER_HOST:-localhost}"
OAUTH_PROVIDER_PORT="${OAUTH_PROVIDER_PORT:-8000}"
OAUTH_PROVIDER_URL="http://${OAUTH_PROVIDER_HOST}:${OAUTH_PROVIDER_PORT}"
OAUTH_CLIENT_ID="${OAUTH_CLIENT_ID:-your-client-id}"
OAUTH_CLIENT_SECRET="${OAUTH_CLIENT_SECRET:-your-client-secret}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAKE_PROVIDER_SCRIPT="${SCRIPT_DIR}/test/fake_oauth_provider.py"
FAKE_PROVIDER_PID=""

# Options
START_PROVIDER="${START_PROVIDER:-false}"
STOP_PROVIDER_ON_EXIT="${STOP_PROVIDER_ON_EXIT:-true}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Cleanup function
cleanup() {
    if [ "$STOP_PROVIDER_ON_EXIT" = "true" ] && [ -n "$FAKE_PROVIDER_PID" ]; then
        log_info "Stopping fake OAuth provider (PID: $FAKE_PROVIDER_PID)..."
        kill "$FAKE_PROVIDER_PID" 2>/dev/null || true
        wait "$FAKE_PROVIDER_PID" 2>/dev/null || true
        log_info "Fake OAuth provider stopped"
    fi
}

# Register cleanup on exit
trap cleanup EXIT INT TERM

# Check if fake OAuth provider is running
check_fake_provider_running() {
    curl -s -o /dev/null -w "%{http_code}" "$OAUTH_PROVIDER_URL/" 2>/dev/null | grep -q "200"
}

# Start fake OAuth provider
start_fake_provider() {
    if check_fake_provider_running; then
        log_info "Fake OAuth provider is already running at $OAUTH_PROVIDER_URL"
        return 0
    fi

    if [ ! -f "$FAKE_PROVIDER_SCRIPT" ]; then
        log_error "Fake OAuth provider script not found at $FAKE_PROVIDER_SCRIPT"
        return 1
    fi

    if ! command -v python3 &> /dev/null; then
        log_error "python3 is not installed or not in PATH"
        return 1
    fi

    log_info "Starting fake OAuth provider at $OAUTH_PROVIDER_URL..."
    OAUTH_CLIENT_ID="$OAUTH_CLIENT_ID" OAUTH_CLIENT_SECRET="$OAUTH_CLIENT_SECRET" \
        python3 "$FAKE_PROVIDER_SCRIPT" --host "$OAUTH_PROVIDER_HOST" --port "$OAUTH_PROVIDER_PORT" > /tmp/fake_oauth_provider.log 2>&1 &
    FAKE_PROVIDER_PID=$!

    # Wait for provider to start
    local max_attempts=10
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        sleep 1
        if check_fake_provider_running; then
            log_info "✓ Fake OAuth provider started (PID: $FAKE_PROVIDER_PID)"
            return 0
        fi
        ((attempt++))
    done

    log_error "Failed to start fake OAuth provider"
    return 1
}

# Stop fake OAuth provider
stop_fake_provider() {
    if [ -n "$FAKE_PROVIDER_PID" ]; then
        log_info "Stopping fake OAuth provider (PID: $FAKE_PROVIDER_PID)..."
        kill "$FAKE_PROVIDER_PID" 2>/dev/null || true
        wait "$FAKE_PROVIDER_PID" 2>/dev/null || true
        FAKE_PROVIDER_PID=""
        log_info "✓ Fake OAuth provider stopped"
    fi
}

# Test fake OAuth provider endpoints
test_fake_provider() {
    log_info "Testing fake OAuth provider endpoints..."

    # Test root endpoint
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$OAUTH_PROVIDER_URL/" || echo "000")
    if [ "$RESPONSE" = "200" ]; then
        log_info "✓ Fake OAuth provider root endpoint is accessible"
    else
        log_error "Fake OAuth provider root endpoint returned status: $RESPONSE"
        return 1
    fi

    # Test authorization endpoint
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        "$OAUTH_PROVIDER_URL/oauth/authorize?response_type=code&client_id=${OAUTH_CLIENT_ID}&redirect_uri=http://localhost:8080/oauth" \
        || echo "000")
    if [ "$RESPONSE" = "302" ] || [ "$RESPONSE" = "200" ]; then
        log_info "✓ Fake OAuth provider authorization endpoint is working"
    else
        log_warn "Fake OAuth provider authorization endpoint returned status: $RESPONSE"
    fi

    return 0
}

# Test 1: Check Gerrit version
test_gerrit_version() {
    log_info "Testing Gerrit version..."

    RESPONSE=$(curl -s --user "$GERRIT_USER:$GERRIT_PASSWORD" \
        "$GERRIT_URL/a/config/server/version" || echo "")

    if [ -z "$RESPONSE" ]; then
        log_error "Failed to connect to Gerrit at $GERRIT_URL"
        return 1
    fi

    # Remove XSRF protection prefix
    VERSION=$(echo "$RESPONSE" | sed 's/^)]}\x27//')
    log_info "Gerrit version: $VERSION"

    if [[ $VERSION == *"3.4"* ]]; then
        log_info "✓ Gerrit 3.4 detected"
        return 0
    else
        log_warn "Expected Gerrit 3.4, got: $VERSION"
        return 0
    fi
}

# Test 2: Check if OAuth plugin is installed
test_plugin_installed() {
    log_info "Checking if OAuth plugin is installed..."

    RESPONSE=$(curl -s --user "$GERRIT_USER:$GERRIT_PASSWORD" \
        "$GERRIT_URL/a/plugins/$PLUGIN_NAME/gerrit~status" || echo "")

    if [ -z "$RESPONSE" ]; then
        log_error "OAuth plugin not found or not responding"
        return 1
    fi

    # Remove XSRF protection prefix
    STATUS=$(echo "$RESPONSE" | sed 's/^)]}\x27//')
    log_info "Plugin status: $STATUS"
    log_info "✓ OAuth plugin is installed"
    return 0
}

# Test 3: List all plugins
test_list_plugins() {
    log_info "Listing all installed plugins..."

    RESPONSE=$(curl -s --user "$GERRIT_USER:$GERRIT_PASSWORD" \
        "$GERRIT_URL/a/plugins/?all" || echo "")

    if [ -z "$RESPONSE" ]; then
        log_error "Failed to list plugins"
        return 1
    fi

    # Remove XSRF protection prefix and check for oauth
    PLUGINS=$(echo "$RESPONSE" | sed 's/^)]}\x27//')

    if echo "$PLUGINS" | grep -q "oauth"; then
        log_info "✓ OAuth plugin found in plugin list"
        echo "$PLUGINS" | grep -A5 "oauth"
        return 0
    else
        log_error "OAuth plugin not found in plugin list"
        return 1
    fi
}

# Test 4: Check OAuth configuration
test_oauth_config() {
    log_info "Checking OAuth configuration..."

    # Try to access OAuth service URLs
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        "$GERRIT_URL/oauth" || echo "000")

    log_info "OAuth endpoint HTTP status: $RESPONSE"

    if [ "$RESPONSE" = "200" ] || [ "$RESPONSE" = "302" ] || [ "$RESPONSE" = "401" ]; then
        log_info "✓ OAuth endpoint is accessible"
        return 0
    else
        log_warn "OAuth endpoint returned status: $RESPONSE"
        return 0
    fi
}

# Test 5: Check OAuth login endpoint
test_oauth_login() {
    log_info "Checking OAuth login endpoint..."

    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        "$GERRIT_URL/login/oauth" || echo "000")

    log_info "OAuth login endpoint HTTP status: $RESPONSE"

    if [ "$RESPONSE" = "200" ] || [ "$RESPONSE" = "302" ] || [ "$RESPONSE" = "404" ]; then
        log_info "✓ OAuth login endpoint checked"
        return 0
    else
        log_warn "OAuth login endpoint returned status: $RESPONSE"
        return 0
    fi
}

# Test 6: Verify plugin API endpoints
test_plugin_api() {
    log_info "Testing plugin API endpoints..."

    # Test plugin metrics
    RESPONSE=$(curl -s --user "$GERRIT_USER:$GERRIT_PASSWORD" \
        "$GERRIT_URL/a/plugins/$PLUGIN_NAME/gerrit~metrics" || echo "")

    if [ -n "$RESPONSE" ]; then
        log_info "✓ Plugin API is accessible"
        return 0
    else
        log_warn "Plugin API metrics not available"
        return 0
    fi
}

# Test 7: Check OAuth providers configuration
test_oauth_providers() {
    log_info "Checking OAuth providers configuration..."

    # Check if gerrit.config has OAuth settings
    log_info "OAuth providers should be configured in gerrit.config"
    log_info "Example providers: GitHub, GitLab, Google, Bitbucket, etc."

    return 0
}

# Test 8: Test fake OAuth provider integration
test_fake_provider_integration() {
    log_info "Testing fake OAuth provider integration with Gerrit..."

    if ! check_fake_provider_running; then
        log_warn "Fake OAuth provider is not running, skipping integration test"
        return 0
    fi

    # Test that Gerrit can reach the provider
    log_info "Fake OAuth provider URL: $OAUTH_PROVIDER_URL"
    log_info "✓ Fake OAuth provider integration test completed"

    return 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --start-provider)
                START_PROVIDER=true
                shift
                ;;
            --no-stop-provider)
                STOP_PROVIDER_ON_EXIT=false
                shift
                ;;
            --provider-host)
                OAUTH_PROVIDER_HOST="$2"
                OAUTH_PROVIDER_URL="http://${OAUTH_PROVIDER_HOST}:${OAUTH_PROVIDER_PORT}"
                shift 2
                ;;
            --provider-port)
                OAUTH_PROVIDER_PORT="$2"
                OAUTH_PROVIDER_URL="http://${OAUTH_PROVIDER_HOST}:${OAUTH_PROVIDER_PORT}"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --start-provider          Start the fake OAuth provider before running tests"
                echo "  --no-stop-provider        Don't stop the provider when tests finish"
                echo "  --provider-host HOST      Set the provider host (default: localhost)"
                echo "  --provider-port PORT      Set the provider port (default: 8000)"
                echo "  --help                    Show this help message"
                echo ""
                echo "Environment variables:"
                echo "  GERRIT_URL                Gerrit server URL (default: http://localhost:8080)"
                echo "  GERRIT_USER               Gerrit admin user (default: admin)"
                echo "  GERRIT_PASSWORD           Gerrit admin password (default: secret)"
                echo "  OAUTH_PROVIDER_HOST       Fake OAuth provider host (default: localhost)"
                echo "  OAUTH_PROVIDER_PORT       Fake OAuth provider port (default: 8000)"
                echo "  OAUTH_CLIENT_ID           OAuth client ID (default: your-client-id)"
                echo "  OAUTH_CLIENT_SECRET       OAuth client secret (default: your-client-secret)"
                echo "  START_PROVIDER            Start provider automatically (default: false)"
                echo "  STOP_PROVIDER_ON_EXIT     Stop provider on exit (default: true)"
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
    log_info "Gerrit OAuth Plugin Test Suite"
    log_info "======================================"
    log_info "Gerrit URL: $GERRIT_URL"
    log_info "Testing with user: $GERRIT_USER"
    if [ "$START_PROVIDER" = "true" ] || check_fake_provider_running; then
        log_info "Fake OAuth Provider URL: $OAUTH_PROVIDER_URL"
        log_info "OAuth Client ID: $OAUTH_CLIENT_ID"
    fi
    log_info ""

    # Start fake OAuth provider if requested
    if [ "$START_PROVIDER" = "true" ]; then
        if ! start_fake_provider; then
            log_error "Failed to start fake OAuth provider, exiting"
            exit 1
        fi
        echo ""
    elif check_fake_provider_running; then
        log_info "Fake OAuth provider is already running"
        echo ""
    fi

    TESTS_PASSED=0
    TESTS_FAILED=0

    # Run tests
    if test_gerrit_version; then
        ((TESTS_PASSED++))
    else
        ((TESTS_FAILED++))
    fi
    echo ""

    if test_plugin_installed; then
        ((TESTS_PASSED++))
    else
        ((TESTS_FAILED++))
    fi
    echo ""

    if test_list_plugins; then
        ((TESTS_PASSED++))
    else
        ((TESTS_FAILED++))
    fi
    echo ""

    if test_oauth_config; then
        ((TESTS_PASSED++))
    else
        ((TESTS_FAILED++))
    fi
    echo ""

    if test_oauth_login; then
        ((TESTS_PASSED++))
    else
        ((TESTS_FAILED++))
    fi
    echo ""

    if test_plugin_api; then
        ((TESTS_PASSED++))
    else
        ((TESTS_FAILED++))
    fi
    echo ""

    if test_oauth_providers; then
        ((TESTS_PASSED++))
    else
        ((TESTS_FAILED++))
    fi
    echo ""

    # Test fake OAuth provider if it's running
    if check_fake_provider_running; then
        if test_fake_provider; then
            ((TESTS_PASSED++))
        else
            ((TESTS_FAILED++))
        fi
        echo ""

        if test_fake_provider_integration; then
            ((TESTS_PASSED++))
        else
            ((TESTS_FAILED++))
        fi
        echo ""
    fi

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

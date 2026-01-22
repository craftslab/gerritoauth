# GitHub OAuth API Test Suite

This test suite validates GitHub OAuth API endpoints including:
- **Authorization URL** (`https://github.com/login/oauth/authorize`)
- **Access Token URL** (`https://github.com/login/oauth/access_token`)
- **User Info URL** (`https://api.github.com/user`)

## Requirements

- `bash` (version 4.0 or higher)
- `curl`
- `python3` (for JSON parsing)
- GitHub OAuth App credentials:
  - Client ID
  - Client Secret

## Getting GitHub OAuth Credentials

1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Click "New OAuth App"
3. Fill in:
   - **Application name**: Your app name
   - **Homepage URL**: Your application URL
   - **Authorization callback URL**: `http://localhost:8080/oauth` (or your redirect URI)
4. Click "Register application"
5. Copy the **Client ID** and generate a **Client Secret**

## Usage

### Basic Usage

Set environment variables and run the test:

```bash
export GITHUB_CLIENT_ID="your-client-id"
export GITHUB_CLIENT_SECRET="your-client-secret"
./test.sh
```

### Using Command Line Arguments

```bash
./test.sh --client-id "your-client-id" --client-secret "your-client-secret"
```

### Custom Configuration

```bash
./test.sh \
  --client-id "your-client-id" \
  --client-secret "your-client-secret" \
  --redirect-uri "http://localhost:8080/oauth" \
  --scope "user:email" \
  --github-root-url "https://github.com/" \
  --github-api-url "https://api.github.com/"
```

### Testing Complete OAuth Flow

To test the complete OAuth flow (authorization code → access token → user info):

1. Run the test script to get the authorization URL:
   ```bash
   ./test.sh --client-id "your-client-id" --client-secret "your-client-secret"
   ```

2. Visit the authorization URL shown in the output

3. Authorize the application in your browser

4. Extract the `code` parameter from the redirect URL

5. Run the test again with the authorization code:
   ```bash
   ./test.sh \
     --client-id "your-client-id" \
     --client-secret "your-client-secret" \
     --authorization-code "your-authorization-code"
   ```

Or using environment variables:

```bash
export GITHUB_CLIENT_ID="your-client-id"
export GITHUB_CLIENT_SECRET="your-client-secret"
export AUTHORIZATION_CODE="your-authorization-code"
./test.sh
```

## Test Coverage

The test suite includes:

1. **Authorization URL Test**
   - Validates URL format
   - Checks required parameters (client_id, response_type, redirect_uri)
   - Tests endpoint accessibility

2. **Access Token URL Test**
   - Validates URL format
   - Tests endpoint with client_id and client_secret
   - Verifies request format and authentication

3. **User Info URL Test**
   - Validates URL format
   - Tests endpoint accessibility
   - Verifies authentication requirements
   - Tests with invalid tokens

4. **Complete OAuth Flow Test** (optional)
   - Exchanges authorization code for access token
   - Retrieves user information with access token
   - Validates response format and required fields

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID | *required* |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret | *required* |
| `REDIRECT_URI` | OAuth redirect URI | `http://localhost:8080/oauth` |
| `SCOPE` | OAuth scope | `user:email` |
| `GITHUB_ROOT_URL` | GitHub root URL | `https://github.com/` |
| `GITHUB_API_URL` | GitHub API URL | `https://api.github.com/` |
| `AUTHORIZATION_CODE` | Authorization code for complete flow test | *optional* |

## Command Line Options

| Option | Description |
|--------|-------------|
| `--client-id ID` | GitHub OAuth client ID |
| `--client-secret SECRET` | GitHub OAuth client secret |
| `--redirect-uri URI` | OAuth redirect URI |
| `--scope SCOPE` | OAuth scope |
| `--github-root-url URL` | GitHub root URL |
| `--github-api-url URL` | GitHub API URL |
| `--authorization-code CODE` | Authorization code for complete flow test |
| `--help` | Show help message |

## GitHub Enterprise Support

To test against GitHub Enterprise, set the root URL and API URL:

```bash
./test.sh \
  --client-id "your-client-id" \
  --client-secret "your-client-secret" \
  --github-root-url "https://github.example.com/" \
  --github-api-url "https://github.example.com/api/v3/"
```

## Example Output

```
======================================
GitHub OAuth API Test Suite
======================================
GitHub Root URL: https://github.com/
GitHub API URL: https://api.github.com/
Redirect URI: http://localhost:8080/oauth
Scope: user:email

[INFO] Testing GitHub Authorization URL...
[INFO] ✓ Authorization URL contains client_id
[INFO] ✓ Authorization URL contains response_type=code
[INFO] ✓ Authorization URL contains redirect_uri
[INFO] ✓ Authorization URL format is valid

[INFO] Testing GitHub Access Token URL...
[INFO] ✓ Access Token URL format is valid

[INFO] Testing GitHub User Info URL...
[INFO] ✓ User Info URL is accessible and requires authentication (HTTP 401)
[INFO] ✓ User Info URL correctly rejects invalid tokens
[INFO] ✓ User Info URL format is valid

======================================
Test Summary
======================================
Tests passed: 4
Tests failed: 0

✓ All tests passed!
```

## Troubleshooting

### Connection Timeouts

If you encounter connection timeouts, GitHub may be unreachable or rate limiting. The tests will show warnings but continue.

### Invalid Client Credentials

Make sure your client ID and client secret are correct. You can verify them in GitHub Settings → Developer settings → OAuth Apps.

### Authorization Code Expired

Authorization codes expire quickly (usually within 10 minutes). If testing the complete flow, use the code immediately after obtaining it.

### Rate Limiting

GitHub API has rate limits. If you see 403 errors, you may have exceeded the rate limit. Wait a few minutes and try again.

## Integration with Gerrit

This test suite validates the GitHub OAuth endpoints that the Gerrit OAuth plugin uses. The endpoints match those configured in `gerrit.config`:

```ini
[plugin "gerrit-oauth-provider-github-oauth"]
    client-id = "your-github-oauth-app-client-id"
    client-secret = "your-github-oauth-app-client-secret"
    root-url = "https://github.com/"
```

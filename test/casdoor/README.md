# Casdoor OAuth Provider Test

This folder provides a minimal docker-compose setup for running Casdoor and a test script to verify OAuth authentication using Client Credentials Grant flow.

## Quick Start

### 1. Start Casdoor

From this directory:

```bash
docker compose up
```

Then open `http://localhost:8000` in your browser.

### 2. Default Login

- **Account**: `built-in/admin`
- **Username**: `admin`
- **Password**: `123`

### 3. Create an OAuth Provider

You can create either a **Custom OAuth Provider** or use a **GitHub OAuth Provider**:

#### Option A: Create an OAuth Custom Provider

1. Log in to Casdoor web UI at `http://localhost:8000`
2. Navigate to **Providers** in the left sidebar
3. Click **Add** to create a new provider
4. Fill in the provider details:
   - **Name**: e.g., `oauth-custom`
   - **Category**: Select `OAuth`
   - **Type**: Select `Custom` (or `OAuth Custom`)
   - **Organization**: Select `built-in` (or your organization)
   - Configure other OAuth settings as needed for your testing scenario
5. Click **Save**

#### Option B: Set Up GitHub OAuth Provider

**Step 1: Create a GitHub OAuth App**

1. Go to [GitHub Settings → Developer settings → OAuth Apps](https://github.com/settings/developers)
2. Click **New OAuth App**
3. Fill in the application details:
   - **Application name**: e.g., `Casdoor Test App`
   - **Homepage URL**: `http://localhost:8000` (or your Casdoor URL)
   - **Authorization callback URL**: `http://localhost:8000/callback` (must match exactly - use your actual Casdoor URL for remote instances)
4. Click **Register application**
5. Copy the **Client ID** and generate a **Client Secret** (click "Generate a new client secret")
6. Save these credentials for the next step

**Step 2: Configure GitHub Provider in Casdoor**

1. In Casdoor UI, navigate to **Providers** in the left sidebar
2. Either edit existing `provider_github` or click **Add** to create a new provider:
   - **Name**: e.g., `provider_github`
   - **Category**: Select `OAuth`
   - **Type**: Select `GitHub`
   - **Organization**: Select `built-in` (or your organization)
3. **Critical**: Fill in the GitHub OAuth App credentials:
   - **Client ID**: Paste the **GitHub OAuth App's Client ID** (from Step 1)
   - **Client Secret**: Paste the **GitHub OAuth App's Client Secret** (from Step 1)
   - **Authorization URL**: `https://github.com/login/oauth/authorize`
   - **Token URL**: `https://github.com/login/oauth/access_token`
   - **User Info URL**: `https://api.github.com/user`
4. Click **Save**

**Important**: The provider must use the **GitHub OAuth App's credentials**, NOT the Casdoor application's client_id/client_secret. Using the wrong credentials will cause GitHub to reject the authorization request.

### 4. Create an Application

1. Navigate to **Applications** in the left sidebar
2. Click **Add** to create a new application
3. Fill in the application details:
   - **Name**: e.g., `test-app`
   - **Organization**: Select `built-in` (or your organization)
   - **Client ID**: Will be auto-generated (or set your own)
   - **Client Secret**: Will be auto-generated (or set your own)
   - **Redirect URLs**: Can be left empty for M2M authentication
   - **Enable Password**: Set to `false` (for Client Credentials Grant)
   - **Enable Client Credentials**: Set to `true` (important!)
   - **Providers**: Link the OAuth provider created in step 3 (e.g., `provider_github` or `oauth-custom`)
4. Click **Save**

### 5. Get Client Credentials

After creating the application, you can find:
- **Client ID**: On the application edit page
- **Client Secret**: On the application edit page (click to reveal)

Example application page URL: `http://localhost:8000/applications/built-in/test-app`

### 6. Run the Test

Set the environment variables and run the test script:

```bash
export CASDOOR_HOST="localhost:8000"
export CASDOOR_CLIENT_ID="your-client-id"
export CASDOOR_CLIENT_SECRET="your-client-secret"

# (Optional) Provider OAuth API checks (Test 4)
# - By default, Test 4 reads auth/token/userinfo URLs from the provider config (requires jq).
# - Set this if your provider is not the default.
export CASDOOR_PROVIDER_ID="admin/provider_oauth_custom"

# Make the script executable (first time only)
chmod +x test.sh

# Run the test
./test.sh
```

Or run with inline environment variables:

```bash
CASDOOR_HOST="localhost:8000" \
CASDOOR_CLIENT_ID="your-client-id" \
CASDOOR_CLIENT_SECRET="your-client-secret" \
CASDOOR_PROVIDER_ID="admin/provider_oauth_custom" \
./test.sh
```

## Testing with Remote Casdoor

To test against a remote Casdoor instance, **either**:

- set `CASDOOR_HOST` to `host:port` (no scheme), **or**
- set `CASDOOR_URL` to a full base URL like `http://host:port` or `https://host` (recommended for HTTPS)

```bash
export CASDOOR_HOST="your-remote-host:8000"
export CASDOOR_CLIENT_ID="your-client-id"
export CASDOOR_CLIENT_SECRET="your-client-secret"

# (Optional) Provider OAuth API checks (Test 4)
export CASDOOR_PROVIDER_ID="admin/provider_oauth_custom"

./test.sh
```

If you have a full URL (like in your log), do this instead:

```bash
export CASDOOR_URL="http://your-remote-host:8000"
export CASDOOR_CLIENT_ID="your-client-id"
export CASDOOR_CLIENT_SECRET="your-client-secret"

# (Optional) Provider OAuth API checks (Test 4)
export CASDOOR_PROVIDER_ID="admin/provider_oauth_custom"

./test.sh
```

Note: If using HTTPS or a different port, prefer setting `CASDOOR_URL` explicitly.

### Provider OAuth API overrides (optional)

If you don't have `jq` (so the script can't parse provider config), or you want to override the provider's endpoints explicitly:

```bash
export OAUTH_AUTH_URL="https://idp.example.com/oauth/authorize"
export OAUTH_TOKEN_URL="https://idp.example.com/oauth/token"
export OAUTH_USERINFO_URL="https://idp.example.com/oauth/userinfo"
```

If you want Test 4b/4c to actually request a token from the provider and call userinfo (only works if the upstream provider supports `client_credentials`):

```bash
export OAUTH_PROVIDER_CLIENT_ID="provider-client-id"
export OAUTH_PROVIDER_CLIENT_SECRET="provider-client-secret"
```

Optional parameters used when probing the auth URL:

```bash
export OAUTH_REDIRECT_URI="http://localhost/callback"
export OAUTH_SCOPE="openid profile email"
export OAUTH_STATE="test-state"
```

## What the Test Does

The test script performs the following checks:

1. **Dependency Check**: Verifies that `curl` (and optionally `jq`) are installed
2. **Health Check**: Verifies that Casdoor is accessible
3. **Configuration Validation**: Checks that client ID and secret are provided
4. **Test 1 - Direct Client Credentials**: Tests API calls using `clientId` and `clientSecret` as GET parameters
5. **Test 2 - Basic Authentication**: Tests API calls using HTTP Basic Authentication with Base64-encoded credentials
6. **Test 3 - OAuth 2.0 Client Credentials Grant**:
   - **3a**: Obtains an access token using Client Credentials Grant flow
   - **3b**: Tests API calls using the access token with Bearer authentication
   - **3c**: Tests API calls using the access token as a GET parameter
7. **Test 4 - OAuth Provider API Endpoints (from Provider config)**:
   - Reads **auth URL**, **token URL**, **userinfo URL** from the Casdoor **Provider** (e.g. `provider_oauth_custom`)
   - **4a**: Checks the auth URL is reachable (usually returns `302` to a login page)
   - **4b**: Optionally tries `client_credentials` against the token URL (only if provider has its own client_id/secret)
   - **4c**: Optionally calls userinfo with the provider token (if 4b produced one)

## Authentication Methods Tested

The test covers all M2M (Machine-to-Machine) authentication methods supported by Casdoor:

1. **Direct Client Credentials** (GET parameters)
   ```
   /api/get-global-providers?clientId=...&clientSecret=...
   ```

2. **HTTP Basic Authentication**
   ```
   Authorization: Basic <base64(clientId:clientSecret)>
   ```

3. **OAuth 2.0 Client Credentials Grant**
   - Step 1: POST to `/api/login/oauth/access_token` with `grant_type=client_credentials`
   - Step 2: Use the returned `access_token` with:
     - Bearer token: `Authorization: Bearer <token>`
     - GET parameter: `?access_token=<token>`

## Requirements

- `curl`: For making HTTP requests
- `jq` (optional): For JSON parsing and better output formatting
- `base64` or `openssl` (optional): For Basic Authentication test

## Stop Casdoor

```bash
docker compose down
```

## Troubleshooting

### "Cannot connect to Casdoor"

- Ensure Casdoor is running: `docker compose ps`
- Check if the port is correct: `docker compose logs`
- Verify the host and port in `CASDOOR_HOST`

### "Failed to obtain access token"

- Verify that the application has **Enable Client Credentials** set to `true`
- Check that the Client ID and Secret are correct
- Ensure the application is in the correct organization

### "API call returned error status"

- Verify that the application has proper permissions
- Check Casdoor logs: `docker compose logs casdoor`
- Ensure the application is not disabled

### "GitHub OAuth shows 'Uh oh! There was an error while loading'"

This error typically occurs when the GitHub authorize URL uses the wrong `client_id`. Common causes:

- **Provider uses Casdoor app credentials instead of GitHub OAuth App credentials**:
  - Check `provider_github` in Casdoor UI
  - Ensure **Client ID** field contains the **GitHub OAuth App's Client ID** (not the Casdoor application's client ID)
  - Ensure **Client Secret** field contains the **GitHub OAuth App's Client Secret** (not the Casdoor application's client secret)

- **GitHub OAuth App callback URL mismatch**:
  - In GitHub OAuth App settings, verify **Authorization callback URL** matches exactly: `http://your-casdoor-host:8000/callback`
  - For remote instances, use the actual Casdoor URL (e.g., `http://localhost:8000/callback`)

- **Verify the authorize URL**:
  - When testing, check the GitHub authorize URL in your browser
  - The `client_id` parameter should be your **GitHub OAuth App's Client ID**, not the Casdoor application's client ID
  - If it shows the Casdoor app's client ID, the provider configuration is incorrect

## References

- [Casdoor Providers: Add an OAuth provider](https://www.casdoor.org/docs/provider/oauth/overview#add-an-oauth-provider)
- [Casdoor Public API: Client Credentials Grant](https://www.casdoor.org/docs/basic/public-api#obtaining-access-tokens-with-client-credentials)
- [Casdoor Try with Docker (Option-1)](https://www.casdoor.org/docs/basic/try-with-docker#option-1-use-the-toy-database)

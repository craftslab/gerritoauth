# Test

## Overview

The fake provider implements a minimal OAuth 2.0 authorization code flow that matches the requirements of the Gerrit OAuth plugin. It provides three main endpoints:

1. **Authorization Endpoint** (`/oauth/authorize`) - Issues authorization codes
2. **Token Endpoint** (`/oauth/token`) - Exchanges authorization codes for access tokens
3. **User Info Endpoint** (`/api/user`) - Returns user information for authenticated requests

## Requirements

- Python 3.6 or higher
- No additional dependencies (uses only Python standard library)

## Starting the Provider

**Option 1: Using the Python script directly**
```bash
cd test
python3 fake_oauth_provider.py
```

**Option 2: Using the wrapper script**
```bash
cd test
chmod +x fake_oauth_provider.sh
./fake_oauth_provider.sh
```

**Option 3: With custom host/port**
```bash
python3 fake_oauth_provider.py --host 0.0.0.0 --port 8000
```

## Environment Variables

You can configure the provider using environment variables:

```bash
export OAUTH_PROVIDER_HOST=0.0.0.0
export OAUTH_PROVIDER_PORT=8000
./fake_oauth_provider.sh
```

## Configuration

The provider uses the following default values (matching `gerrit.config`):

- **Client ID**: `your-client-id` (configurable via `OAUTH_CLIENT_ID` environment variable)
- **Client Secret**: `your-client-secret` (configurable via `OAUTH_CLIENT_SECRET` environment variable)
- **Authorization URL**: `http://localhost:8000/oauth/authorize`
- **Token URL**: `http://localhost:8000/oauth/token`
- **Resource URL**: `http://localhost:8000/api/user`

### Configuring Client Credentials

The `client-id` and `client-secret` must match between:
1. `gerrit.config` - `[plugin "gerrit-oauth-provider-uac-oauth"]` section
2. Fake OAuth provider - environment variables or defaults

**Default values** (used if not specified):
- Client ID: `your-client-id`
- Client Secret: `your-client-secret`

**To use custom client credentials:**

1. Set environment variables when starting the provider:
   ```bash
   export OAUTH_CLIENT_ID="my-custom-client-id"
   export OAUTH_CLIENT_SECRET="my-custom-secret"
   python3 fake_oauth_provider.py
   ```

2. Update `gerrit.config` to match:
   ```ini
   [plugin "gerrit-oauth-provider-uac-oauth"]
       client-id = "my-custom-client-id"
       client-secret = "my-custom-secret"
       ...
   ```

### Test User

The provider returns the following test user information:

```json
{
  "id": "12345",
  "email": "testuser@example.com",
  "login": "testuser",
  "name": "Test User"
}
```

## Updating gerrit.config

To use this fake provider with Gerrit, update your `gerrit.config`:

```ini
[plugin "gerrit-oauth-provider"]
    enabled = true
[plugin "gerrit-oauth-provider-uac-oauth"]
    client-id = "your-client-id"
    client-secret = "your-client-secret"
    token-url = "http://localhost:8000/oauth/token"
    authorize-url = "http://localhost:8000/oauth/authorize"
    resource-url = "http://localhost:8000/api/user"
```

## OAuth Flow

The provider implements the standard OAuth 2.0 authorization code flow:

1. **Authorization Request**: Gerrit redirects user to `/oauth/authorize?response_type=code&client_id=...&redirect_uri=...`
2. **Authorization Response**: Provider redirects back to Gerrit with an authorization code
3. **Token Request**: Gerrit exchanges the code for an access token via POST to `/oauth/token`
4. **Token Response**: Provider returns an access token
5. **User Info Request**: Gerrit requests user information from `/api/user` with the access token
6. **User Info Response**: Provider returns user JSON with `id`, `email`, `login`, and `name` fields

## Testing

1. Start the provider:
   ```bash
   python3 fake_oauth_provider.py
   ```

2. Test authorization endpoint:
   ```bash
   curl "http://localhost:8000/oauth/authorize?response_type=code&client_id=your-client-id&redirect_uri=http://localhost:8080/oauth"
   ```

3. Test token endpoint (replace `CODE` with the code from step 2):
   ```bash
   curl -X POST "http://localhost:8000/oauth/token?grant_type=authorization_code" \
     -d "code=CODE" \
     -d "client_id=your-client-id" \
     -d "client_secret=your-client-secret" \
     -d "redirect_uri=http://localhost:8080/oauth"
   ```

4. Test user info endpoint (replace `TOKEN` with the access_token from step 3):
   ```bash
   curl -H "Authorization: Bearer TOKEN" http://localhost:8000/api/user
   ```

# UAC OAuth test (Gerrit 3.4)

This folder contains a bash test script that validates UAC OAuth behavior for Gerrit 3.4.

## What it checks

- LDAP user HTTP password login works via `/a/accounts/self`.
- The LDAP account ID matches an existing account (no new account is created).
- Optional post-OAuth check: the UAC external ID exists and the account ID is unchanged.

## Requirements

- Gerrit 3.4 running with the UAC OAuth plugin.
- An existing LDAP-linked Gerrit account.
- Admin HTTP credentials for REST API access.

## Environment variables

Required:

- `GERRIT_URL` (e.g. `https://gerrit.example.com`)
- `ADMIN_USER`
- `ADMIN_HTTP_PASSWORD`
- `LDAP_USERNAME`
- `LDAP_HTTP_PASSWORD`
- `EXPECTED_ACCOUNT_ID`

Optional:

- `MODE` (default: `pre`) - set to `post` after OAuth linking.
- `UAC_EXTERNAL_ID` (default: `uac-oauth:<LDAP_USERNAME>`)

## Usage

Pre-link check (before UAC OAuth login):

```bash
MODE=pre GERRIT_URL=https://gerrit.example.com \
ADMIN_USER=admin ADMIN_HTTP_PASSWORD=... \
LDAP_USERNAME=ldapuser LDAP_HTTP_PASSWORD=... \
EXPECTED_ACCOUNT_ID=1000001 \
./test.sh
```

Post-link check (after UAC OAuth login):

```bash
MODE=post GERRIT_URL=https://gerrit.example.com \
ADMIN_USER=admin ADMIN_HTTP_PASSWORD=... \
LDAP_USERNAME=ldapuser LDAP_HTTP_PASSWORD=... \
EXPECTED_ACCOUNT_ID=1000001 \
./test.sh
```

## Notes

- The script does not perform the OAuth browser flow; run `MODE=post` only after the user has logged in via UAC OAuth.
- If your UAC external ID format differs, set `UAC_EXTERNAL_ID` explicitly.

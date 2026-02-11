# UAC OAuth test (Gerrit 2.13)

This folder contains a bash test script that validates UAC OAuth behavior for Gerrit 2.13.

## What it checks

- LDAP user HTTP password login works via `/a/accounts/self`.
- The LDAP account ID matches an existing account (no new account is created).
- Optional post-OAuth check: the UAC external ID exists and the account ID is unchanged.

## Requirements

- Gerrit 2.13 running with the UAC OAuth plugin.
- An LDAP server reachable by Gerrit.
- An LDAP-linked Gerrit account created via LDAP auth before OAuth.
- Admin HTTP credentials for REST API access.

## LDAP server setup (test)

Use a local OpenLDAP container to create the LDAP user and verify LDAP auth before OAuth.

```bash
docker run -d --name test-ldap \
	-p 389:389 -p 636:636 \
	-e LDAP_ORGANISATION="Example" \
	-e LDAP_DOMAIN="example.org" \
	-e LDAP_ADMIN_PASSWORD="admin" \
	osixia/openldap:1.5.0
```

Create a test user (adjust DN to match your Gerrit LDAP config):

```bash
cat <<'EOF' | ldapadd -x -H ldap://localhost:389 \
	-D "cn=admin,dc=example,dc=org" -w admin
dn: uid=ldapuser,dc=example,dc=org
objectClass: inetOrgPerson
sn: User
cn: LDAP User
uid: ldapuser
mail: ldapuser@example.org
userPassword: ldappass
EOF
```

Before running this test, log in to Gerrit using LDAP auth so the LDAP account is created and note the resulting account ID (use it as `EXPECTED_ACCOUNT_ID`).

## Gerrit LDAP config example

Minimal `gerrit.config` snippet that matches the test OpenLDAP container above:

```ini
[auth]
	type = LDAP
[ldap]
	server = ldap://localhost:389
	username = cn=admin,dc=example,dc=org
	password = admin
	accountBase = dc=example,dc=org
	accountPattern = (uid=${username})
	accountFullName = cn
	accountEmailAddress = mail
```

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
- To mark a user inactive in Gerrit, run `ssh -p <port> <host> gerrit set-account --inactive <USER>`.

## Reference

- [gerrit-set-account](https://gerrit-documentation.storage.googleapis.com/Documentation/2.13.9/cmd-set-account.html)

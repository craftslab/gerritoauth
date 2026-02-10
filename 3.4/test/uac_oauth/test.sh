#!/usr/bin/env bash
set -euo pipefail

# Test UAC OAuth provider behavior for Gerrit 3.4.
# Verifies:
# - LDAP user HTTP password works (via /a/accounts/self)
# - Account ID matches expected LDAP account ID
# - Optional: after OAuth linking, UAC external ID exists and account ID is unchanged

required_env=(
  GERRIT_URL
  ADMIN_USER
  ADMIN_HTTP_PASSWORD
  LDAP_USERNAME
  LDAP_HTTP_PASSWORD
  EXPECTED_ACCOUNT_ID
)

for var in "${required_env[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "Missing env var: ${var}" >&2
    exit 1
  fi
done

MODE="${MODE:-pre}"
UAC_EXTERNAL_ID="${UAC_EXTERNAL_ID:-uac-oauth:${LDAP_USERNAME}}"

if [[ "${MODE}" != "pre" && "${MODE}" != "post" ]]; then
  echo "MODE must be 'pre' or 'post' (default: pre)." >&2
  exit 1
fi

strip_gerrit_json() {
  python - <<'PY'
import sys
raw = sys.stdin.read()
prefix = ")]}'"
if raw.startswith(prefix):
    raw = raw[len(prefix):]
    if raw.startswith("\n"):
        raw = raw[1:]
print(raw)
PY
}

urlencode() {
  python - <<'PY' "$1"
import sys
from urllib.parse import quote
print(quote(sys.argv[1], safe=""))
PY
}

json_get_account_id() {
  python - <<'PY'
import json
import sys
obj = json.load(sys.stdin)
print(obj.get("_account_id", ""))
PY
}

json_get_username() {
  python - <<'PY'
import json
import sys
obj = json.load(sys.stdin)
print(obj.get("username", ""))
PY
}

json_contains_external_id() {
  python - <<'PY' "$1"
import json
import sys
needle = sys.argv[1]
arr = json.load(sys.stdin)
print("true" if needle in arr else "false")
PY
}

curl_admin() {
  curl -sS -u "${ADMIN_USER}:${ADMIN_HTTP_PASSWORD}" "$@"
}

curl_ldap() {
  curl -sS -u "${LDAP_USERNAME}:${LDAP_HTTP_PASSWORD}" "$@"
}

GERRIT_URL="${GERRIT_URL%/}"
ENC_LDAP_USER="$(urlencode "${LDAP_USERNAME}")"

account_json=$(curl_admin "${GERRIT_URL}/a/accounts/${ENC_LDAP_USER}")
account_json=$(printf "%s" "${account_json}" | strip_gerrit_json)
account_id=$(printf "%s" "${account_json}" | json_get_account_id)
account_username=$(printf "%s" "${account_json}" | json_get_username)

if [[ -z "${account_id}" ]]; then
  echo "Failed to resolve account for ${LDAP_USERNAME}" >&2
  exit 1
fi

if [[ "${account_id}" != "${EXPECTED_ACCOUNT_ID}" ]]; then
  echo "Account ID mismatch for ${LDAP_USERNAME}: expected ${EXPECTED_ACCOUNT_ID}, got ${account_id}" >&2
  exit 1
fi

echo "Account lookup OK: username=${account_username}, account_id=${account_id}"

self_json=$(curl_ldap "${GERRIT_URL}/a/accounts/self")
self_json=$(printf "%s" "${self_json}" | strip_gerrit_json)
self_account_id=$(printf "%s" "${self_json}" | json_get_account_id)

if [[ "${self_account_id}" != "${EXPECTED_ACCOUNT_ID}" ]]; then
  echo "HTTP password login failed or account mismatch: expected ${EXPECTED_ACCOUNT_ID}, got ${self_account_id}" >&2
  exit 1
fi

echo "HTTP password login OK: account_id=${self_account_id}"

external_ids_json=$(curl_admin "${GERRIT_URL}/a/accounts/${EXPECTED_ACCOUNT_ID}/external.ids")
external_ids_json=$(printf "%s" "${external_ids_json}" | strip_gerrit_json)

if [[ "${MODE}" == "post" ]]; then
  has_uac=$(printf "%s" "${external_ids_json}" | json_contains_external_id "${UAC_EXTERNAL_ID}")
  if [[ "${has_uac}" != "true" ]]; then
    echo "Missing UAC external ID after OAuth linking: ${UAC_EXTERNAL_ID}" >&2
    exit 1
  fi
  echo "UAC external ID present: ${UAC_EXTERNAL_ID}"
else
  echo "MODE=pre: skipping UAC external ID check (set MODE=post after OAuth login)."
fi

echo "All checks passed."

#!/usr/bin/env bash
set -euo pipefail

# Idempotent Keycloak bootstrap via Admin REST API.
# Creates:
#  - realm: openclaw-bff (KEYCLOAK_REALM)
#  - client: openclaw-bff-api (KEYCLOAK_CLIENT_ID)
#      - public client
#      - direct access grants enabled (so tests can fetch tokens using password grant)
#      - standard flow enabled
#  - test user: testuser / testpassword
#
# Keycloak is started in docker-compose with admin bootstrap user.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

KC_BASE="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
KC_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
KC_ADMIN_PASS="${KEYCLOAK_ADMIN_PASSWORD:-admin}"

REALM="${KEYCLOAK_REALM:-openclaw-bff}"
CLIENT_ID="${KEYCLOAK_CLIENT_ID:-openclaw-bff-api}"

TEST_USER="${KEYCLOAK_TEST_USER:-testuser}"
TEST_PASS="${KEYCLOAK_TEST_PASSWORD:-testpassword}"

echo "Waiting Keycloak..."
"$ROOT_DIR/scripts/wait_for_http.sh" "$KC_BASE/realms/master" 180

token() {
  curl -fsS -X POST "$KC_BASE/realms/master/protocol/openid-connect/token"     -H "Content-Type: application/x-www-form-urlencoded"     -d "grant_type=password"     -d "client_id=admin-cli"     -d "username=$KC_ADMIN_USER"     -d "password=$KC_ADMIN_PASS" | python -c "import sys, json; print(json.load(sys.stdin)['access_token'])"
}

ADMIN_TOKEN="$(token)"
AUTHZ=(-H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json")

# 1) Ensure realm
REALM_STATUS="$(curl -s -o /dev/null -w "%{http_code}" "${AUTHZ[@]}" "$KC_BASE/admin/realms/$REALM" || true)"
if [[ "$REALM_STATUS" != "200" ]]; then
  echo "Creating realm: $REALM"
  curl -fsS -X POST "${AUTHZ[@]}" "$KC_BASE/admin/realms" -d @- <<JSON
{
  "realm": "$REALM",
  "enabled": true,
  "displayName": "OpenClaw BFF",
  "sslRequired": "external"
}
JSON
else
  echo "Realm exists: $REALM"
fi

# 2) Ensure client
CLIENTS="$(curl -fsS "${AUTHZ[@]}" "$KC_BASE/admin/realms/$REALM/clients?clientId=$CLIENT_ID")"
CLIENT_UUID="$(python - <<'PY'
import sys, json
arr=json.load(sys.stdin)
print(arr[0]["id"] if arr else "")
PY
<<<"$CLIENTS")"

if [[ -z "$CLIENT_UUID" ]]; then
  echo "Creating client: $CLIENT_ID"
  curl -fsS -X POST "${AUTHZ[@]}" "$KC_BASE/admin/realms/$REALM/clients" -d @- <<JSON
{
  "clientId": "$CLIENT_ID",
  "name": "OpenClaw BFF API",
  "enabled": true,
  "publicClient": true,
  "protocol": "openid-connect",
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "serviceAccountsEnabled": false,
  "redirectUris": ["http://localhost:*/*"],
  "webOrigins": ["http://localhost:*"]
}
JSON
else
  echo "Client exists: $CLIENT_ID"
fi

# 3) Ensure test user
USERS="$(curl -fsS "${AUTHZ[@]}" "$KC_BASE/admin/realms/$REALM/users?username=$TEST_USER")"
USER_ID="$(python - <<'PY'
import sys, json
arr=json.load(sys.stdin)
print(arr[0]["id"] if arr else "")
PY
<<<"$USERS")"

if [[ -z "$USER_ID" ]]; then
  echo "Creating user: $TEST_USER"
  curl -fsS -X POST "${AUTHZ[@]}" "$KC_BASE/admin/realms/$REALM/users" -d @- <<JSON
{
  "username": "$TEST_USER",
  "enabled": true,
  "emailVerified": true
}
JSON

  # fetch id
  USERS="$(curl -fsS "${AUTHZ[@]}" "$KC_BASE/admin/realms/$REALM/users?username=$TEST_USER")"
  USER_ID="$(python - <<'PY'
import sys, json
arr=json.load(sys.stdin)
print(arr[0]["id"] if arr else "")
PY
<<<"$USERS")"
else
  echo "User exists: $TEST_USER"
fi

echo "Setting password for user: $TEST_USER"
curl -fsS -X PUT "${AUTHZ[@]}" "$KC_BASE/admin/realms/$REALM/users/$USER_ID/reset-password" -d @- <<JSON
{
  "type": "password",
  "value": "$TEST_PASS",
  "temporary": false
}
JSON

echo "Keycloak initialized."
echo "Realm: $REALM"
echo "ClientId: $CLIENT_ID"
echo "Test user: $TEST_USER / $TEST_PASS"

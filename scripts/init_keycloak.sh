#!/usr/bin/env bash
set -euo pipefail

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

# ---- helpers ----

json_get() {
  # Extract a field from JSON via python (robust against empty/non-json).
  # Usage: json_get 'j.get("access_token","")' <<<"$json"
  local expr="$1"
  python3 -c "import sys,json
try:
  j=json.load(sys.stdin)
  v=($expr)
  print('' if v is None else v)
except Exception:
  print('')"
}

get_admin_token() {
  # Robust token fetch with retries (Keycloak may be 'up' but token endpoint still warming).
  local token_url="$KC_BASE/realms/master/protocol/openid-connect/token"
  local i
  for i in {1..30}; do
    set +e
    local resp
    resp="$(curl -sS -X POST "$token_url" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=password" \
      -d "client_id=admin-cli" \
      -d "username=$KC_ADMIN_USER" \
      -d "password=$KC_ADMIN_PASS")"
    local rc=$?
    set -e

    if [[ $rc -ne 0 || -z "$resp" ]]; then
      sleep 1
      continue
    fi

    local token
    token="$(json_get 'j.get("access_token","")' <<<"$resp")"

    if [[ -n "$token" ]]; then
      echo "$token"
      return 0
    fi
    sleep 1
  done

  echo "ERROR: Unable to obtain admin token from Keycloak." >&2
  echo "Check admin credentials and Keycloak logs." >&2
  return 1
}

ADMIN_TOKEN="$(get_admin_token)"
AUTH_HEADER=(-H "Authorization: Bearer $ADMIN_TOKEN")

http_json() {
  # Usage: http_json METHOD URL [JSON_BODY]
  # Prints body to stdout. Returns non-zero if status >= 400.
  local method="$1"
  local url="$2"
  local body="${3:-}"

  local tmp_body
  tmp_body="$(mktemp)"

  # Include auth header if present (safe with set -u)
  local auth_args=()
  if declare -p AUTH_HEADER >/dev/null 2>&1; then
    auth_args=("${AUTH_HEADER[@]}")
  fi

  local status
  if [[ -n "$body" ]]; then
    status="$(curl -sS -o "$tmp_body" -w "%{http_code}" -X "$method" \
      "${auth_args[@]}" \
      -H "Content-Type: application/json" \
      "$url" \
      -d "$body")"
  else
    status="$(curl -sS -o "$tmp_body" -w "%{http_code}" -X "$method" \
      "${auth_args[@]}" \
      -H "Content-Type: application/json" \
      "$url")"
  fi

  if [[ "$status" -ge 400 ]]; then
    echo "ERROR: $method $url -> HTTP $status" >&2
    echo "Body:" >&2
    cat "$tmp_body" >&2
    rm -f "$tmp_body"
    return 1
  fi

  cat "$tmp_body"
  rm -f "$tmp_body"
}

# ---- 1) Ensure realm exists ----
set +e
realm_status="$(curl -sS -o /dev/null -w "%{http_code}" "${AUTH_HEADER[@]}" "$KC_BASE/admin/realms/$REALM")"
set -e

if [[ "$realm_status" != "200" ]]; then
  echo "Creating realm: $REALM"
  http_json POST "$KC_BASE/admin/realms" "$(cat <<JSON
{
  "realm": "$REALM",
  "enabled": true,
  "displayName": "OpenClaw BFF",
  "sslRequired": "external"
}
JSON
)" >/dev/null
else
  echo "Realm exists: $REALM"
fi

# ---- 2) Ensure client exists ----
clients_json="$(curl -sS "${AUTH_HEADER[@]}" "$KC_BASE/admin/realms/$REALM/clients?clientId=$CLIENT_ID")"
client_uuid="$(python3 -c 'import sys,json
try:
  arr=json.load(sys.stdin)
  print(arr[0]["id"] if arr else "")
except Exception:
  print("")' <<<"$clients_json")"

if [[ -z "$client_uuid" ]]; then
  echo "Creating client: $CLIENT_ID"
  http_json POST "$KC_BASE/admin/realms/$REALM/clients" "$(cat <<JSON
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
)" >/dev/null
else
  echo "Client exists: $CLIENT_ID"
fi

# ---- 3) Ensure test user exists ----
users_json="$(curl -sS "${AUTH_HEADER[@]}" "$KC_BASE/admin/realms/$REALM/users?username=$TEST_USER")"
user_id="$(python3 -c 'import sys,json
try:
  arr=json.load(sys.stdin)
  print(arr[0]["id"] if arr else "")
except Exception:
  print("")' <<<"$users_json")"

if [[ -z "$user_id" ]]; then
  echo "Creating user: $TEST_USER"
  http_json POST "$KC_BASE/admin/realms/$REALM/users" "$(cat <<JSON
{
  "username": "$TEST_USER",
  "enabled": true,
  "emailVerified": true
}
JSON
)" >/dev/null

  # Re-fetch
  users_json="$(curl -sS "${AUTH_HEADER[@]}" "$KC_BASE/admin/realms/$REALM/users?username=$TEST_USER")"
  user_id="$(python3 -c 'import sys,json
try:
  arr=json.load(sys.stdin)
  print(arr[0]["id"] if arr else "")
except Exception:
  print("")' <<<"$users_json")"
else
  echo "User exists: $TEST_USER"
fi

if [[ -z "$user_id" ]]; then
  echo "ERROR: Could not resolve user id for $TEST_USER" >&2
  echo "Raw response was:" >&2
  echo "$users_json" >&2
  exit 1
fi

# ---- 4) Set password (idempotent) ----
echo "Setting password for user: $TEST_USER"
http_json PUT "$KC_BASE/admin/realms/$REALM/users/$user_id/reset-password" "$(cat <<JSON
{
  "type": "password",
  "value": "$TEST_PASS",
  "temporary": false
}
JSON
)" >/dev/null

echo "Keycloak initialized."
echo "Realm: $REALM"
echo "ClientId: $CLIENT_ID"
echo "Test user: $TEST_USER / $TEST_PASS"
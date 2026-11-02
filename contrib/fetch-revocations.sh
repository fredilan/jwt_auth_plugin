#!/bin/bash
# Fetches the MQTT revocation list from the SousChef API into the plugin's revocation_file.
# Run by flashmq-revocations.timer. On any error the previous file stays in place, so the
# plugin keeps enforcing the last good list.
#
# Config: /etc/flashmq/revocations.env (mode 600, owner root)
#   API_URL=https://api.souscheftech.com        # base URL, no trailing slash
#   API_VERSION=v2
#   OAUTH_CLIENT_ID=<broker client identifier>   # OAuth2 client with the `broker` scope
#   OAUTH_CLIENT_SECRET=<secret>
#   REVOCATION_FILE=/etc/flashmq/revocations.txt # same as plugin_opt_revocation_file
set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/flashmq/revocations.env}"
# shellcheck source=/dev/null
source "$CONFIG_FILE"

: "${API_URL:?}" "${OAUTH_CLIENT_ID:?}" "${OAUTH_CLIENT_SECRET:?}"
API_VERSION="${API_VERSION:-v2}"
REVOCATION_FILE="${REVOCATION_FILE:-/etc/flashmq/revocations.txt}"
HEADER='# FlashMQ jwt_auth_plugin revocation list'

TOKEN="$(curl -sS --fail --max-time 20 -X POST "$API_URL/oauth/v2/token" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode "client_id=$OAUTH_CLIENT_ID" \
  --data-urlencode "client_secret=$OAUTH_CLIENT_SECRET" \
  --data-urlencode scope=broker \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"

if [[ -z "$TOKEN" ]]; then
  echo "No access token from $API_URL/oauth/v2/token" >&2
  exit 1
fi

TMP_FILE="$(mktemp "$(dirname "$REVOCATION_FILE")/.revocations.XXXXXX")"
trap 'rm -f "$TMP_FILE"' EXIT

curl -sS --fail --max-time 30 -H "Authorization: Bearer $TOKEN" \
  "$API_URL/api/$API_VERSION/broker/revocations" -o "$TMP_FILE"

if ! head -n 1 "$TMP_FILE" | grep -qF "$HEADER"; then
  echo "Unexpected response from the revocation endpoint; keeping $REVOCATION_FILE" >&2
  exit 1
fi

# Unchanged list → leave the file (and its mtime) alone, so the plugin doesn't reload.
if [[ -f "$REVOCATION_FILE" ]] && cmp -s <(grep -v '^#' "$TMP_FILE") <(grep -v '^#' "$REVOCATION_FILE"); then
  exit 0
fi

chmod 0644 "$TMP_FILE"
mv -f "$TMP_FILE" "$REVOCATION_FILE"
trap - EXIT
echo "Updated $REVOCATION_FILE: $(grep -vc '^#' "$REVOCATION_FILE" || true) entries"

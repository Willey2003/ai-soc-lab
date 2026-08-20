#!/bin/bash
set -euo pipefail

REQUIRED_VARS=(
    "AIRIA_API_URL"
    "AIRIA_API_KEY"
    "LOCAL_API_KEY"
)

for var in "${REQUIRED_VARS[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        echo "ERROR: Required environment variable $var is not set" >&2
        exit 1
    fi
done

mkdir -p /var/lib/wazuh-airia-forwarder
chown -R wazuh-airia:wazuh-airia /var/lib/wazuh-airia-forwarder

if [[ ! -r /var/ossec/logs/alerts/alerts.json ]]; then
    echo "WARNING: Cannot read Wazuh alerts file, will retry..." >&2
fi

exec "$@"
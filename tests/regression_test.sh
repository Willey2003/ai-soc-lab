#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

ENV_FILE="${PROJECT_ROOT}/docker/.env"

source "${ENV_FILE}"

PASS=0
FAIL=0

test_endpoint() {
    local name="$1"
    local url="$2"
    local expected_code="${3:-200}"
    local headers="${4:-}"
    
    echo -n "Testing ${name}... "
    
    if [[ -n "${headers}" ]]; then
        response=$(curl -s -w "\n%{http_code}" ${headers} "${url}" 2>/dev/null || echo -e "\n000")
    else
        response=$(curl -s -w "\n%{http_code}" "${url}" 2>/dev/null || echo -e "\n000")
    fi
    
    http_code=$(echo "${response}" | tail -n1)
    body=$(echo "${response}" | head -n-1)
    
    if [[ "${http_code}" == "${expected_code}" ]]; then
        echo "PASS (HTTP ${http_code})"
        ((PASS++))
        return 0
    else
        echo "FAIL (HTTP ${http_code}, expected ${expected_code})"
        echo "Response: ${body}"
        ((FAIL++))
        return 1
    fi
}

test_json_field() {
    local name="$1"
    local url="$2"
    local field="$3"
    local expected="${4:-}"
    local headers="${5:-}"
    
    echo -n "Testing ${name}.${field}... "
    
    if [[ -n "${headers}" ]]; then
        response=$(curl -s ${headers} "${url}" 2>/dev/null || echo "{}")
    else
        response=$(curl -s "${url}" 2>/dev/null || echo "{}")
    fi
    
    value=$(echo "${response}" | jq -r "${field}" 2>/dev/null || echo "null")
    
    if [[ "${value}" != "null" && "${value}" != "" ]]; then
        if [[ -n "${expected}" && "${value}" != "${expected}" ]]; then
            echo "FAIL (got '${value}', expected '${expected}')"
            ((FAIL++))
            return 1
        else
            echo "PASS (value: ${value})"
            ((PASS++))
            return 0
        fi
    else
        echo "FAIL (field not found or null)"
        ((FAIL++))
        return 1
    fi
}

echo "=== AI + SOC Lab Regression Tests ==="
echo ""

# Wazuh Indexer
echo "--- Wazuh Indexer ---"
test_endpoint "Wazuh Indexer Health" "https://localhost:9200/_cluster/health" 200 "-k -u admin:${WAZUH_ADMIN_PASSWORD}"
test_json_field "Wazuh Indexer" "https://localhost:9200/_cluster/health" ".status" "green" "-k -u admin:${WAZUH_ADMIN_PASSWORD}"

# Wazuh Manager
echo ""
echo "--- Wazuh Manager ---"
test_endpoint "Wazuh Manager API" "https://localhost:55000" 200 "-k -u wazuh-api:${WAZUH_API_PASSWORD}"
test_json_field "Wazuh Manager" "https://localhost:55000" ".status" "running" "-k -u wazuh-api:${WAZUH_API_PASSWORD}"

# NetAlertX
echo ""
echo "--- NetAlertX ---"
test_endpoint "NetAlertX Web UI" "http://localhost:20211/health" 200
test_endpoint "NetAlertX GraphQL" "http://localhost:20212/devices" 200 "-H \"Authorization: Bearer ${NETALERTX_API_TOKEN}\""
test_json_field "NetAlertX Devices" "http://localhost:20212/devices" ".success" "true" "-H \"Authorization: Bearer ${NETALERTX_API_TOKEN}\""

# Airia Forwarder
echo ""
echo "--- Airia Forwarder ---"
test_endpoint "Forwarder Health" "http://localhost:8010/health" 200
test_json_field "Forwarder Health" "http://localhost:8010/health" ".alerts_readable" "true" "-H \"X-API-Key: ${HELPER_API_KEY}\""
test_json_field "Forwarder Health" "http://localhost:8010/health" ".analyses_writable" "true" "-H \"X-API-Key: ${HELPER_API_KEY}\""
test_endpoint "Forwarder Latest Analysis" "http://localhost:8010/api/latest" 200 "-H \"X-API-Key: ${HELPER_API_KEY}\""
test_json_field "Forwarder Latest" "http://localhost:8010/api/latest" ".risk_score" "" "-H \"X-API-Key: ${HELPER_API_KEY}\""

# Grafana
echo ""
echo "--- Grafana ---"
test_endpoint "Grafana Health" "http://localhost:3000/api/health" 200 "-u admin:${GRAFANA_ADMIN_PASSWORD}"
test_json_field "Grafana Health" "http://localhost:3000/api/health" ".database" "ok" "-u admin:${GRAFANA_ADMIN_PASSWORD}"

# Data source tests
echo ""
echo "--- Grafana Data Sources ---"
ds_response=$(curl -s -u "admin:${GRAFANA_ADMIN_PASSWORD}" "http://localhost:3000/api/datasources" 2>/dev/null || echo "[]")
wazuh_ds=$(echo "${ds_response}" | jq -r '.[] | select(.name=="Wazuh OpenSearch") | .id')
netalertx_ds=$(echo "${ds_response}" | jq -r '.[] | select(.name=="NetAlertX Infinity") | .id')
airia_ds=$(echo "${ds_response}" | jq -r '.[] | select(.name=="Airia Wazuh Forwarder") | .id')

if [[ -n "${wazuh_ds}" && "${wazuh_ds}" != "null" ]]; then
    echo "Wazuh OpenSearch datasource: PASS (id: ${wazuh_ds})"
    ((PASS++))
else
    echo "Wazuh OpenSearch datasource: FAIL (not found)"
    ((FAIL++))
fi

if [[ -n "${netalertx_ds}" && "${netalertx_ds}" != "null" ]]; then
    echo "NetAlertX Infinity datasource: PASS (id: ${netalertx_ds})"
    ((PASS++))
else
    echo "NetAlertX Infinity datasource: FAIL (not found)"
    ((FAIL++))
fi

if [[ -n "${airia_ds}" && "${airia_ds}" != "null" ]]; then
    echo "Airia Wazuh Forwarder datasource: PASS (id: ${airia_ds})"
    ((PASS++))
else
    echo "Airia Wazuh Forwarder datasource: FAIL (not found)"
    ((FAIL++))
fi

# Dashboard test
echo ""
echo "--- Grafana Dashboard ---"
dash_response=$(curl -s -u "admin:${GRAFANA_ADMIN_PASSWORD}" "http://localhost:3000/api/dashboards/uid/network-security-ai-operations" 2>/dev/null || echo "{}")
dash_title=$(echo "${dash_response}" | jq -r '.dashboard.title' 2>/dev/null || echo "")
if [[ "${dash_title}" == "Network Security and AI Operations" ]]; then
    echo "Dashboard found: PASS"
    ((PASS++))
else
    echo "Dashboard found: FAIL (title: ${dash_title})"
    ((FAIL++))
fi

# End-to-end test: Generate FIM event and verify flow
echo ""
echo "--- End-to-End Flow Test ---"
TEST_FILE="/tmp/soc-lab-test-$(date +%s).txt"
echo "Test file created at $(date)" > "${TEST_FILE}"
sleep 5
echo "Test file modified at $(date)" >> "${TEST_FILE}"
sleep 5
rm "${TEST_FILE}"
sleep 5

echo "Waiting for event processing..."
sleep 10

# Check if forwarder received the event
latest=$(curl -s -H "X-API-Key: ${HELPER_API_KEY}" "http://localhost:8010/api/latest" 2>/dev/null || echo "{}")
event_name=$(echo "${latest}" | jq -r '.alert_name' 2>/dev/null || echo "")
if [[ -n "${event_name}" && "${event_name}" != "null" && "${event_name}" != "No Airia analysis received yet" ]]; then
    echo "End-to-end FIM event flow: PASS (alert: ${event_name})"
    ((PASS++))
else
    echo "End-to-end FIM event flow: FAIL (no analysis received)"
    ((FAIL++))
fi

echo ""
echo "=== Test Summary ==="
echo "Passed: ${PASS}"
echo "Failed: ${FAIL}"

if [[ ${FAIL} -gt 0 ]]; then
    echo ""
    echo "Some tests failed. Check the logs for details."
    exit 1
else
    echo ""
    echo "All tests passed!"
    exit 0
fi
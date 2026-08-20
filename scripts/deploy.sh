#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

ENV_FILE="${PROJECT_ROOT}/docker/.env"
COMPOSE_FILE="${PROJECT_ROOT}/docker/docker-compose.yml"

usage() {
    cat <<EOF
Usage: $0 [COMMAND]

Commands:
  up          Start all services
  down        Stop all services
  restart     Restart all services
  logs        Show logs (follow)
  status      Show service status
  test        Run integration tests
  backup      Backup persistent data
  restore     Restore from backup
  generate-secrets  Generate secure secrets for .env

Environment:
  Set ENV_FILE to use a different .env file (default: ${ENV_FILE})
EOF
}

generate_secrets() {
    echo "Generating secure secrets..."
    cat > "${ENV_FILE}" <<EOL
# AI + SOC Lab - Environment Configuration
# Generated on $(date)

# Wazuh
WAZUH_ADMIN_PASSWORD=$(openssl rand -hex 32)
WAZUH_API_PASSWORD=$(openssl rand -hex 32)

# Grafana
GRAFANA_ADMIN_PASSWORD=$(openssl rand -hex 32)

# Airia (get from Airia cloud console)
AIRIA_API_URL=
AIRIA_API_KEY=

# Local forwarder API key
HELPER_API_KEY=$(openssl rand -hex 32)

# Network
BIND_HOST=192.168.0.50
SCAN_SUBNET=192.168.0.0/24

# NetAlertX (generated after first login)
NETALERTX_API_TOKEN=
EOL
    chmod 600 "${ENV_FILE}"
    echo "Secrets generated at ${ENV_FILE}"
    echo "IMPORTANT: Fill in AIRIA_API_URL and AIRIA_API_KEY from Airia console"
    echo "IMPORTANT: Fill in NETALERTX_API_TOKEN after first NetAlertX login"
}

check_env() {
    if [[ ! -f "${ENV_FILE}" ]]; then
        echo "ERROR: ${ENV_FILE} not found. Run 'generate-secrets' first."
        exit 1
    fi
    source "${ENV_FILE}"
    
    required_vars=(
        "WAZUH_ADMIN_PASSWORD"
        "WAZUH_API_PASSWORD"
        "GRAFANA_ADMIN_PASSWORD"
        "AIRIA_API_URL"
        "AIRIA_API_KEY"
        "HELPER_API_KEY"
    )
    
    missing=()
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" || "${!var}" == "CHANGE_ME_"* ]]; then
            missing+=("${var}")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "ERROR: Missing or unset required variables:"
        printf '  %s\n' "${missing[@]}"
        exit 1
    fi
}

cmd_up() {
    check_env
    echo "Starting AI + SOC Lab stack..."
    docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" up -d
    echo "Waiting for services to be healthy..."
    sleep 10
    docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" ps
}

cmd_down() {
    check_env
    echo "Stopping AI + SOC Lab stack..."
    docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" down
}

cmd_restart() {
    check_env
    docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" restart
}

cmd_logs() {
    check_env
    docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" logs -f "${@:2}"
}

cmd_status() {
    check_env
    docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" ps
}

cmd_test() {
    check_env
    echo "Running integration tests..."
    
    # Test Wazuh Indexer
    echo "Testing Wazuh Indexer..."
    curl -k -u "admin:${WAZUH_ADMIN_PASSWORD}" "https://localhost:9200/_cluster/health" | jq .
    
    # Test Wazuh Manager
    echo "Testing Wazuh Manager..."
    curl -k -u "wazuh-api:${WAZUH_API_PASSWORD}" "https://localhost:55000" | jq .
    
    # Test NetAlertX
    echo "Testing NetAlertX..."
    curl -s "http://localhost:20211/health" | jq .
    curl -s -H "Authorization: Bearer ${NETALERTX_API_TOKEN}" "http://localhost:20212/devices" | jq .
    
    # Test Airia Forwarder
    echo "Testing Airia Forwarder..."
    curl -s -H "X-API-Key: ${HELPER_API_KEY}" "http://localhost:8010/health" | jq .
    curl -s -H "X-API-Key: ${HELPER_API_KEY}" "http://localhost:8010/api/latest" | jq .
    
    # Test Grafana
    echo "Testing Grafana..."
    curl -s -u "admin:${GRAFANA_ADMIN_PASSWORD}" "http://localhost:3000/api/health" | jq .
    
    echo "All tests passed!"
}

cmd_backup() {
    check_env
    BACKUP_DIR="${PROJECT_ROOT}/backups/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "${BACKUP_DIR}"
    
    echo "Backing up to ${BACKUP_DIR}..."
    
    # Backup Wazuh data
    docker run --rm \
        -v soc-lab_wazuh-indexer-data:/data \
        -v "${BACKUP_DIR}:/backup" \
        alpine tar czf /backup/wazuh-indexer-data.tar.gz -C /data .
    
    docker run --rm \
        -v soc-lab_wazuh-manager-data:/data \
        -v "${BACKUP_DIR}:/backup" \
        alpine tar czf /backup/wazuh-manager-data.tar.gz -C /data .
    
    docker run --rm \
        -v soc-lab_wazuh-manager-logs:/data \
        -v "${BACKUP_DIR}:/backup" \
        alpine tar czf /backup/wazuh-manager-logs.tar.gz -C /data .
    
    docker run --rm \
        -v soc-lab_netalertx-data:/data \
        -v "${BACKUP_DIR}:/backup" \
        alpine tar czf /backup/netalertx-data.tar.gz -C /data .
    
    docker run --rm \
        -v soc-lab_forwarder-data:/data \
        -v "${BACKUP_DIR}:/backup" \
        alpine tar czf /backup/forwarder-data.tar.gz -C /data .
    
    docker run --rm \
        -v soc-lab_grafana-data:/data \
        -v "${BACKUP_DIR}:/backup" \
        alpine tar czf /backup/grafana-data.tar.gz -C /data .
    
    # Backup configs
    cp -r "${PROJECT_ROOT}/docker/config" "${BACKUP_DIR}/"
    cp "${ENV_FILE}" "${BACKUP_DIR}/.env"
    
    echo "Backup complete: ${BACKUP_DIR}"
}

cmd_restore() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: $0 restore <backup-directory>"
        exit 1
    fi
    
    BACKUP_DIR="$2"
    if [[ ! -d "${BACKUP_DIR}" ]]; then
        echo "ERROR: Backup directory not found: ${BACKUP_DIR}"
        exit 1
    fi
    
    echo "Restoring from ${BACKUP_DIR}..."
    
    # Stop services first
    cmd_down
    
    # Restore volumes
    for volume in wazuh-indexer-data wazuh-manager-data wazuh-manager-logs netalertx-data forwarder-data grafana-data; do
        if [[ -f "${BACKUP_DIR}/${volume}.tar.gz" ]]; then
            echo "Restoring ${volume}..."
            docker run --rm \
                -v "soc-lab_${volume}:/data" \
                -v "${BACKUP_DIR}:/backup" \
                alpine sh -c "rm -rf /data/* && tar xzf /backup/${volume}.tar.gz -C /data"
        fi
    done
    
    # Restore configs
    cp -r "${BACKUP_DIR}/config" "${PROJECT_ROOT}/docker/"
    cp "${BACKUP_DIR}/.env" "${ENV_FILE}"
    
    echo "Restore complete. Run '$0 up' to start services."
}

case "${1:-}" in
    up)
        cmd_up
        ;;
    down)
        cmd_down
        ;;
    restart)
        cmd_restart
        ;;
    logs)
        cmd_logs "$@"
        ;;
    status)
        cmd_status
        ;;
    test)
        cmd_test
        ;;
    backup)
        cmd_backup
        ;;
    restore)
        cmd_restore "$@"
        ;;
    generate-secrets)
        generate_secrets
        ;;
    *)
        usage
        exit 1
        ;;
esac
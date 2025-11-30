#!/bin/bash
# =============================================================================
# DDoS Defense System - Quick Start Script (FIXED)
# =============================================================================
# Usage: ./start.sh [up|down|logs|status|restart|clean]
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/docker"
DATA_DIR="$SCRIPT_DIR/data"
LOGS_DIR="$SCRIPT_DIR/logs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_banner() {
    echo -e "${GREEN}"
    echo "=============================================="
    echo "    🛡️  DDoS Defense System"
    echo "=============================================="
    echo -e "${NC}"
}

check_prerequisites() {
    echo "Checking prerequisites..."

    command -v docker >/dev/null || { echo -e "${RED}Docker not installed${NC}"; exit 1; }
    docker compose version >/dev/null || { echo -e "${RED}Docker Compose plugin missing${NC}"; exit 1; }

    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}WARNING: Run with sudo for XDP & permissions${NC}"
    fi

    echo -e "${GREEN}✓ Prerequisites OK${NC}"
    echo ""
}

detect_network_interface() {
    echo "Detecting network interface..."

    DETECTED_INTERFACE=$(ip route | awk '/default/ {print $5}' | head -n1)
    [ -z "$DETECTED_INTERFACE" ] && DETECTED_INTERFACE="ens33"

    export NETWORK_INTERFACE="$DETECTED_INTERFACE"
    export CAPTURE_INTERFACE="$DETECTED_INTERFACE"

    echo -e "${GREEN}✓ Using interface: $NETWORK_INTERFACE${NC}"
    echo ""
}

is_cluster_running() {
    cd "$DOCKER_DIR"
    docker compose ps --services --filter "status=running" | grep -q ddos
}

fix_permissions() {
    echo -e "${BLUE}Fixing data directory permissions for Elasticsearch...${NC}"

    mkdir -p "$DATA_DIR/elasticsearch" "$DATA_DIR/kibana" "$DATA_DIR/redis" "$LOGS_DIR"

    # Correct ownership (Elasticsearch runs as UID 1000, GID 0)
    chown -R 1000:0 "$DATA_DIR/elasticsearch"
    chmod -R 775 "$DATA_DIR/elasticsearch"

    # Safe for other services
    chown -R 1000:0 "$DATA_DIR/kibana" "$DATA_DIR/redis"
    chmod -R 775 "$DATA_DIR/kibana" "$DATA_DIR/redis"

    echo -e "${GREEN}✓ Permissions fixed${NC}"
}

clean_data() {
    echo -e "${BLUE}Cleaning all data (fresh start)...${NC}"

    rm -rf "$DATA_DIR/elasticsearch/"* "$DATA_DIR/kibana/"* "$DATA_DIR/redis/"* "$LOGS_DIR/"* || true
    fix_permissions
}

stop_services() {
    echo -e "${BLUE}Stopping services...${NC}"
    cd "$DOCKER_DIR"
    docker compose down || true
    echo -e "${GREEN}✓ Stopped${NC}"
}

start_services() {
    print_banner
    check_prerequisites
    detect_network_interface
    fix_permissions

    if is_cluster_running; then
        echo -e "${YELLOW}Cluster running → restart & clean${NC}"
        stop_services
        clean_data
    fi

    echo -e "${BLUE}Starting containers...${NC}"
    cd "$DOCKER_DIR"

    NETWORK_INTERFACE="$NETWORK_INTERFACE" CAPTURE_INTERFACE="$CAPTURE_INTERFACE" \
        docker compose up -d --build

    echo -e "${GREEN}✓ Stack starting...${NC}"
    echo "Kibana        → http://localhost:5601"
    echo "Elasticsearch → http://localhost:9200"
    echo "Redis         → localhost:6379"
    echo ""
    echo -e "${YELLOW}Wait 2–3 minutes for Elasticsearch healthcheck${NC}"
}

show_logs() {
    cd "$DOCKER_DIR"
    docker compose logs -f "${@:2}"
}

show_status() {
    cd "$DOCKER_DIR"
    docker compose ps
    docker inspect --format='Elasticsearch health: {{.State.Health.Status}}' ddos-elasticsearch 2>/dev/null || true
}

restart_services() {
    cd "$DOCKER_DIR"
    docker compose restart
}

clean_restart() {
    stop_services
    clean_data
    start_services
}

# Main
case "${1:-up}" in
    up|start) start_services ;;
    down|stop) stop_services ;;
    logs) show_logs "$@" ;;
    status|ps) show_status ;;
    restart) restart_services ;;
    clean) clean_restart ;;
    *)
        echo "Usage: $0 [up|down|logs|status|restart|clean]"
        exit 1
        ;;
esac

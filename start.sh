#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

[ "$EUID" -ne 0 ] && err "Run as root: sudo ./start.sh"

log "Stopping old containers..."
docker stop ddos-app ddos-redis ddos-elasticsearch ddos-kibana 2>/dev/null || true
docker rm ddos-app ddos-redis ddos-elasticsearch ddos-kibana 2>/dev/null || true
cd docker && docker compose down 2>/dev/null || true && cd ..

log "Cleaning data..."
rm -rf data/* logs/* 2>/dev/null || true
mkdir -p data/elasticsearch data/kibana data/redis logs
chown -R 1000:0 data && chmod -R 775 data

log "Detecting NIC..."
NIC=$(ip route | awk '/default/ {print $5}' | head -n1)
[ -z "$NIC" ] && NIC="ens33"
export NETWORK_INTERFACE="$NIC"
export CAPTURE_INTERFACE="$NIC"
log "Using: $NIC"

log "Finding bpftool..."
BPFTOOL=""
for p in /usr/lib/linux-tools-*/bpftool; do
    P=$(readlink -f $p 2>/dev/null || echo "")
    [ -f "$P" ] && [ $(stat -c%s "$P" 2>/dev/null || echo 0) -gt 100000 ] && BPFTOOL="$P" && break
done
[ -z "$BPFTOOL" ] && err "bpftool not found. Install: apt-get install linux-tools-generic"
log "Found: $BPFTOOL"
sed -i "s|/usr/lib/linux-tools-.*/bpftool|$BPFTOOL|g" docker/docker-compose.yml

log "Building XDP..."
[ ! -f app/vmlinux.h ] && bpftool btf dump file /sys/kernel/btf/vmlinux format c > app/vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/bpf -Iapp -c app/xdp_ip_blacklist.c -o app/xdp_ip_blacklist.o || err "XDP build failed"
log "XDP ready"

log "Starting services..."
cd docker && docker compose build && docker compose up -d && cd ..

log "✓ System running!"
echo ""
echo "Kibana: http://localhost:5601"
echo "Wait 3-5 min for Elasticsearch"
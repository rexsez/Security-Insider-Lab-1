#!/bin/bash
# =============================================================================
# Build XDP Program Outside Docker (Standalone)
# =============================================================================
# This script compiles the XDP program once on your development machine
# and generates the .o file that gets copied into the container.
#
# Run this script whenever you modify xdp_ip_blacklist.c
# =============================================================================

set -e

echo "=============================================="
echo "  XDP Program Build Script (CO-RE/libbpf)"
echo "=============================================="
echo ""

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XDP_SOURCE="$SCRIPT_DIR/app/xdp_ip_blacklist.c"
XDP_OUTPUT="$SCRIPT_DIR/app/xdp_ip_blacklist.o"
VMLINUX_H="$SCRIPT_DIR/app/vmlinux.h"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Check dependencies
log_info "Checking build dependencies..."
missing_deps=()

for cmd in clang llvm-strip bpftool; do
    if ! command -v $cmd &> /dev/null; then
        missing_deps+=("$cmd")
    fi
done

if [ ${#missing_deps[@]} -ne 0 ]; then
    log_error "Missing dependencies: ${missing_deps[*]}"
    echo ""
    echo "Install with:"
    echo "  Ubuntu/Debian: sudo apt-get install clang llvm bpftool libbpf-dev linux-tools-common"
    echo "  Fedora/RHEL:   sudo dnf install clang llvm bpftool libbpf-devel"
    echo ""
    exit 1
fi

log_success "All build tools found"
echo ""

# Verify source file exists
if [ ! -f "$XDP_SOURCE" ]; then
    log_error "Source file not found: $XDP_SOURCE"
    exit 1
fi

# Generate vmlinux.h if needed
if [ ! -f "$VMLINUX_H" ]; then
    log_info "Generating vmlinux.h from kernel BTF..."
    
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        log_error "/sys/kernel/btf/vmlinux not found"
        echo ""
        echo "Your kernel doesn't have BTF support enabled."
        echo ""
        echo "Solutions:"
        echo "  1. Use a kernel with CONFIG_DEBUG_INFO_BTF=y"
        echo "  2. Download vmlinux.h from BTF Hub:"
        echo "     https://github.com/aquasecurity/btfhub"
        echo "  3. Use a prebuilt vmlinux.h for your kernel version"
        echo ""
        exit 1
    fi
    
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX_H"
    log_success "Generated $VMLINUX_H"
else
    log_success "Using existing $VMLINUX_H"
fi

echo ""

# Compile XDP program
log_info "Compiling XDP program..."
echo "  Source: $XDP_SOURCE"
echo "  Output: $XDP_OUTPUT"
echo ""

clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/bpf \
    -I"$(dirname "$VMLINUX_H")" \
    -c "$XDP_SOURCE" \
    -o "$XDP_OUTPUT"

if [ $? -ne 0 ]; then
    log_error "Compilation failed"
    exit 1
fi

# Strip debug symbols to reduce size (optional)
if command -v llvm-strip &> /dev/null; then
    llvm-strip -g "$XDP_OUTPUT" 2>/dev/null || true
fi

echo ""
log_success "Compilation successful!"
echo ""

# Show file info
echo "Object file details:"
ls -lh "$XDP_OUTPUT"
echo ""

# Verify the object file
if command -v readelf &> /dev/null; then
    log_info "BPF object sections:"
    readelf -S "$XDP_OUTPUT" | grep -E "Name|xdp|maps" | head -20
    echo ""
fi

if command -v bpftool &> /dev/null; then
    log_info "BPF program info:"
    bpftool prog show 2>/dev/null || echo "  (no programs currently loaded)"
    echo ""
fi

# Success summary
echo "=============================================="
echo "  ✓ Build Complete!"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  1. Commit these files to your repository:"
echo "     - $XDP_OUTPUT"
echo "     - $VMLINUX_H"
echo ""
echo "  2. Build Docker image:"
echo "     cd docker && docker-compose build"
echo ""
echo "  3. Deploy the system:"
echo "     sudo ./start.sh up"
echo ""
echo "Note: Rebuild whenever you modify $XDP_SOURCE"
echo ""
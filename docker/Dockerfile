# =============================================================================
# DDoS Defense Application Container (libbpf/CO-RE version)
# =============================================================================
# Contains: NFStream + ML Inference + XDP Controller (no BCC)
# Base: Ubuntu 22.04
# =============================================================================
FROM ubuntu:22.04 AS builder

LABEL maintainer="DDoS Defense System"
LABEL description="Real-time DDoS defense with XDP (CO-RE), ML, and NFStream"

ENV DEBIAN_FRONTEND=noninteractive

# =============================================================================
# Build Stage: Compile XDP Program
# =============================================================================
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-common \
    linux-tools-generic \
    bpftool \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy XDP source
COPY app/xdp_ip_blacklist.c /build/

# Generate vmlinux.h from host BTF (if not provided)
# Note: This requires kernel BTF support on build host
RUN if [ ! -f /build/vmlinux.h ]; then \
        if [ -f /sys/kernel/btf/vmlinux ]; then \
            bpftool btf dump file /sys/kernel/btf/vmlinux format c > /build/vmlinux.h; \
        else \
            echo "WARNING: /sys/kernel/btf/vmlinux not found - using fallback"; \
            echo "// Fallback vmlinux.h - replace with proper BTF dump" > /build/vmlinux.h; \
        fi \
    fi

# Compile XDP program to BPF object
RUN clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/bpf \
    -c xdp_ip_blacklist.c \
    -o xdp_ip_blacklist.o

# =============================================================================
# Runtime Stage
# =============================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# =============================================================================
# Install Runtime Dependencies (NO BCC, NO linux-headers)
# =============================================================================
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    libbpf1 \
    bpftool \
    linux-tools-common \
    linux-tools-generic \
    libpcap-dev \
    tcpdump \
    iproute2 \
    net-tools \
    libffi-dev \
    curl \
    wget \
    procps \
    supervisor \
    redis-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Create symlink for bpftool
# =============================================================================
RUN find /usr/lib/linux-tools -name "bpftool" -type f 2>/dev/null | head -1 | xargs -I {} ln -sf {} /usr/sbin/bpftool || true

# =============================================================================
# Install Python Dependencies
# =============================================================================
RUN pip3 install --no-cache-dir \
    numpy \
    scikit-learn \
    joblib \
    nfstream \
    redis \
    requests \
    urllib3 \
    python-dateutil

# =============================================================================
# Create Application Directory Structure
# =============================================================================
WORKDIR /app
RUN mkdir -p /app/logs /app/models

# =============================================================================
# Copy Pre-compiled XDP Object from Builder
# =============================================================================
COPY --from=builder /build/xdp_ip_blacklist.o /app/

# =============================================================================
# Copy Application Files
# =============================================================================
# Copy ML models
COPY models/trained_models.pkl /app/models/
COPY models/preprocessing_objects.pkl /app/models/

# Copy Python scripts
COPY app/nfstream_agent.py /app/
COPY app/ml_infer_service.py /app/
COPY app/xdp_controller.py /app/

# Copy entrypoint and supervisor config
COPY docker/entrypoint.sh /app/
COPY docker/supervisord.conf /etc/supervisor/conf.d/ddos-defense.conf

# Make scripts executable
RUN chmod +x /app/*.py /app/entrypoint.sh

# =============================================================================
# Environment Variables (defaults, can be overridden)
# =============================================================================
ENV NETWORK_INTERFACE=ens33
ENV CAPTURE_INTERFACE=ens33
ENV REDIS_HOST=127.0.0.1
ENV REDIS_PORT=6379
ENV ES_HOST=http://127.0.0.1:9200
ENV ES_USER=elastic
ENV ES_PASS=jgYsL5-kztDUSd8HyiNd
ENV ARTIFACTS_DIR=/app/models
ENV XDP_OBJECT_PATH=/app/xdp_ip_blacklist.o
ENV CONFIDENCE_THRESHOLD=0.65
ENV PYTHONUNBUFFERED=1

# =============================================================================
# Entrypoint
# =============================================================================
ENTRYPOINT ["/app/entrypoint.sh"]
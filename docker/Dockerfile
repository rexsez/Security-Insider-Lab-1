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
RUN apt-get update && apt-get install -y --fix-missing \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-common \
    linux-tools-generic \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy XDP source and vmlinux.h
COPY app/xdp_ip_blacklist.c /build/
COPY app/vmlinux.h /build/

# Compile XDP program to BPF object
RUN clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/bpf \
    -I/build \
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
RUN apt-get update && apt-get install -y --fix-missing \
    python3 \
    python3-pip \
    python3-dev \
    libbpf0 \
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
# Create symlink for bpftool - must match host kernel
# =============================================================================
RUN KERNEL_VERSION=$(ls /usr/lib/linux-tools/ | grep -E '^[0-9]' | sort -V | tail -1) && \
    if [ -f "/usr/lib/linux-tools/${KERNEL_VERSION}/bpftool" ]; then \
        ln -sf "/usr/lib/linux-tools/${KERNEL_VERSION}/bpftool" /usr/sbin/bpftool && \
        ln -sf "/usr/lib/linux-tools/${KERNEL_VERSION}/bpftool" /usr/bin/bpftool; \
    fi && \
    bpftool version || echo "WARNING: bpftool not available"

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
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --fix-missing \
    clang llvm libbpf-dev linux-tools-common linux-tools-generic \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY app/xdp_ip_blacklist.c app/vmlinux.h /build/

RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/bpf -I/build \
    -c xdp_ip_blacklist.c -o xdp_ip_blacklist.o

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --fix-missing \
    python3 python3-pip python3-dev libbpf0 \
    linux-tools-common linux-tools-generic \
    libpcap-dev tcpdump iproute2 net-tools libffi-dev \
    curl wget procps supervisor redis-tools \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir numpy scikit-learn joblib nfstream redis requests urllib3 python-dateutil

WORKDIR /app
RUN mkdir -p /app/logs /app/models /app/dashboards

COPY --from=builder /build/xdp_ip_blacklist.o /app/
COPY models/ /app/models/
COPY app/*.py /app/
COPY docker/entrypoint.sh /app/
COPY docker/supervisord.conf /etc/supervisor/conf.d/ddos-defense.conf

RUN chmod +x /app/*.py /app/entrypoint.sh

ENV NETWORK_INTERFACE=ens33
ENV REDIS_HOST=127.0.0.1
ENV REDIS_PORT=6379
ENV ES_HOST=http://127.0.0.1:9200
ENV ES_USER=elastic
ENV ES_PASS=jgYsL5-kztDUSd8HyiNd
ENV XDP_OBJECT_PATH=/app/xdp_ip_blacklist.o
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/app/entrypoint.sh"]
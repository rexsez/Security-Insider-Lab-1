// xdp_ip_blacklist.c
// CO-RE XDP IP blacklist with dual blocking and per-drop logging
// For use with libbpf (no BCC runtime compilation)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Maximum number of blacklisted IPs
#define MAX_BLACKLIST_ENTRIES 10000
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

// Renamed to avoid vmlinux.h collision
struct xdp_blacklist_entry {
    __u64 detection_event_id_high;  // UUID high 64 bits
    __u64 detection_event_id_low;   // UUID low 64 bits
    __u64 block_timestamp;          // When this IP was blacklisted
    __u32 drop_count;               // Number of packets dropped from this IP
};

// Structure for per-drop event logging
struct drop_event {
    __u32 src_ip;
    __u64 timestamp;
    __u64 detection_event_id_high;
    __u64 detection_event_id_low;
    __u8 drop_reason;  // 1=IP_BLACKLIST, 2=CONTENT_FILTER
};

// BPF Maps - libbpf syntax
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLACKLIST_ENTRIES);
    __type(key, __u32);
    __type(value, struct xdp_blacklist_entry);
} ip_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_cnt SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} drop_events SEC(".maps");

// Helper: Check if payload starts with "Test Data"
static __always_inline int mem_match_testdata(void *ptr, void *end) {
    char pattern[] = "Test Data";
    int len = 9;  // Length of "Test Data"

    if ((void *)ptr + len > end)
        return 0;

    unsigned char *p = (unsigned char *)ptr;

    // Manual unrolled loop for BPF verifier
    if (len > 0 && p[0] != pattern[0]) return 0;
    if (len > 1 && p[1] != pattern[1]) return 0;
    if (len > 2 && p[2] != pattern[2]) return 0;
    if (len > 3 && p[3] != pattern[3]) return 0;
    if (len > 4 && p[4] != pattern[4]) return 0;
    if (len > 5 && p[5] != pattern[5]) return 0;
    if (len > 6 && p[6] != pattern[6]) return 0;
    if (len > 7 && p[7] != pattern[7]) return 0;
    if (len > 8 && p[8] != pattern[8]) return 0;

    return 1;
}

// Helper: Send drop event to userspace
static __always_inline void log_drop_event(struct xdp_md *ctx, __u32 src_ip,
                                           struct xdp_blacklist_entry *entry,
                                           __u8 reason) {
    struct drop_event event = {};
    event.src_ip = src_ip;
    event.timestamp = bpf_ktime_get_ns();
    event.drop_reason = reason;

    if (entry) {
        event.detection_event_id_high = entry->detection_event_id_high;
        event.detection_event_id_low = entry->detection_event_id_low;
    }

    bpf_perf_event_output(ctx, &drop_events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
}

// Main XDP Program
SEC("xdp")
int xdp_ip_blacklist_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    __u32 src_ip = BPF_CORE_READ(ip, saddr);  // Source IP in network byte order

    // ========================================
    // CHECK 1: IP Blacklist Lookup
    // ========================================
    struct xdp_blacklist_entry *entry = bpf_map_lookup_elem(&ip_blacklist, &src_ip);
    if (entry) {
        // IP is blacklisted - increment drop counter
        __sync_fetch_and_add(&entry->drop_count, 1);

        // Update global drop counter
        __u32 key = 0;
        __u64 *val = bpf_map_lookup_elem(&drop_cnt, &key);
        if (val)
            __sync_fetch_and_add(val, 1);

        // Log drop event with detection_event_id
        log_drop_event(ctx, src_ip, entry, 1);  // Reason: 1 = IP_BLACKLIST

        return XDP_DROP;
    }

    // ========================================
    // CHECK 2: Content-Based Filter (Smoke Test)
    // ========================================

    // Only check TCP packets for content
    __u8 protocol = BPF_CORE_READ(ip, protocol);
    if (protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Read IHL - first byte of IP header contains version+IHL
    __u8 ihl_byte;
    bpf_probe_read_kernel(&ihl_byte, 1, (void *)ip);
    __u32 ihl_len = (ihl_byte & 0x0F) * 4;
    if (ihl_len < sizeof(*ip))
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ihl_len;
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    // Read TCP data offset - byte 12 of TCP header contains doff
    __u8 doff_byte;
    bpf_probe_read_kernel(&doff_byte, 1, (void *)tcp + 12);
    __u32 tcp_hdr_len = ((doff_byte >> 4) & 0x0F) * 4;
    if (tcp_hdr_len < sizeof(*tcp))
        return XDP_PASS;

    void *payload = (void *)tcp + tcp_hdr_len;
    if (payload >= data_end)
        return XDP_PASS;

    // Check for "Test Data" pattern
    if (mem_match_testdata(payload, data_end)) {
        // Update global drop counter
        __u32 key = 0;
        __u64 *val = bpf_map_lookup_elem(&drop_cnt, &key);
        if (val)
            __sync_fetch_and_add(val, 1);

        // Log drop event (no detection_event_id for content filter)
        log_drop_event(ctx, src_ip, NULL, 2);  // Reason: 2 = CONTENT_FILTER

        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
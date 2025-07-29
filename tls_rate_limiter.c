#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

// --- Rate Limiting Definitions ---

// Check for compile-time overrides, otherwise use default.
#ifndef MAX_HANDSHAKES_PER_TW
#define MAX_HANDSHAKES_PER_TW 5
#endif

#ifndef TIME_WINDOW_NS
#define TIME_WINDOW_NS 1000000000ULL
#endif

// --- Application & Protocol Definitions ---

// TARGET_PORT is the TCP port to monitor.
#define TARGET_PORT 6379

// TLS_CONTENT_TYPE_HANDSHAKE is the value for the TLS content type
// that indicates a handshake message.
#define TLS_CONTENT_TYPE_HANDSHAKE 22

// TLS_HANDSHAKE_TYPE_CLIENT_HELLO is the value for the TLS handshake
// type that indicates a "Client Hello" message.
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 1

// This struct will be the value in our eBPF map.
// It now includes a spin lock for safe concurrent access.
struct handshake_data {
  struct bpf_spin_lock lock; // Spin lock to prevent race conditions on update.
  __u64 timestamp; // Timestamp of the first handshake in the current window.
  __u32 count;     // Count of handshakes within the current window.
};

// The struct is "packed" to ensure its memory layout matches the
// on-the-wire format of the TLS record exactly. This is crucial for
// correctly parsing the packet data.
struct tls_hdr {
  __u8 content_type;
  __u16 version;
  __u16 length;
  __u8 handshake_type;
} __attribute__((packed));

// Definition of the eBPF map to store rate-limiting state.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct handshake_data);
} handshake_ratelimit_map SEC(".maps");

// License for the eBPF program. Required for the program to be loaded.
char __license[] SEC("license") = "GPL";

// --- PARSING HELPER FUNCTIONS (Defined Once) ---

// parse_ethernet_header checks if the packet is an Ethernet frame and
// if it contains an IP packet.
static __always_inline int parse_ethernet_header(void **data, void *data_end,
                                                 struct ethhdr **eth) {
  *eth = *data;
  // Boundary check: Ensure the Ethernet header is within the packet bounds.
  if ((void *)*eth + sizeof(**eth) > data_end)
    return 0;
  *data = (void *)*eth +
          sizeof(**eth); // Move data pointer past the Ethernet header.
  // Check if the protocol is IP.
  if ((*eth)->h_proto != __constant_htons(ETH_P_IP))
    return 0;
  return 1;
}

// parse_ip_header checks if the packet has a valid IP header.
static __always_inline int parse_ip_header(void **data, void *data_end,
                                           struct iphdr **ip) {
  *ip = *data;
  // Boundary check: Ensure the IP header is within the packet bounds.
  if ((void *)*ip + sizeof(**ip) > data_end)
    return 0;
  __u8 ip_header_size = (*ip)->ihl * 4; // Calculate IP header size.
  if (ip_header_size < sizeof(**ip))
    return 0;
  // Boundary check: Ensure the full IP header is within packet bounds.
  if ((void *)*ip + ip_header_size > data_end)
    return 0;
  *data = (void *)*ip + ip_header_size; // Move data pointer past the IP header.
  // Check if the protocol is TCP.
  if ((*ip)->protocol != IPPROTO_TCP)
    return 0;
  return 1;
}

// parse_tcp_header checks for a valid TCP header and returns it.
static __always_inline struct tcphdr *parse_tcp_header(void **data,
                                                       void *data_end) {
  struct tcphdr *tcp = *data;
  // Boundary check: Ensure the fixed-size TCP header is within packet bounds.
  if ((void *)tcp + sizeof(*tcp) > data_end)
    return NULL;
  __u8 tcp_header_size = tcp->doff * 4; // Calculate TCP header size.
  if (tcp_header_size < sizeof(*tcp))
    return NULL;
  // Boundary check: Ensure the full TCP header is within packet bounds.
  if ((void *)tcp + tcp_header_size > data_end)
    return NULL;
  *data =
      (void *)tcp + tcp_header_size; // Move data pointer past the TCP header.
  return tcp;
}

// is_tls_client_hello checks if the payload is a TLS Client Hello message.
static __always_inline int is_tls_client_hello(void *data, void *data_end) {
  // Boundary check: Ensure the TLS header is within the packet bounds.
  if (data + sizeof(struct tls_hdr) > data_end)
    return 0;
  struct tls_hdr *tls = data;
  // Check for the specific TLS content and handshake types.
  if (tls->content_type == TLS_CONTENT_TYPE_HANDSHAKE &&
      tls->handshake_type == TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
    return 1;
  return 0;
}

// --- MAIN XDP PROGRAM ---

SEC("xdp")
int detect_and_rate_limit_tls(struct xdp_md *ctx) {
  // Get pointers to the start and end of the packet data.
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth;
  struct iphdr *ip;
  struct tcphdr *tcp;

  // Sequentially parse packet headers. If any parser fails, pass the packet.
  if (!parse_ethernet_header(&data, data_end, &eth))
    return XDP_PASS;
  if (!parse_ip_header(&data, data_end, &ip))
    return XDP_PASS;

  tcp = parse_tcp_header(&data, data_end);
  if (!tcp)
    return XDP_PASS;
  // Check if the destination port is the Redis TLS port.
  if (tcp->dest != __constant_htons(TARGET_PORT))
    return XDP_PASS;
  // Check if the payload is a TLS Client Hello.
  if (!is_tls_client_hello(data, data_end))
    return XDP_PASS;

  // --- GLOBAL RATE LIMITING LOGIC ---
  __u32 key = 0; // Use a single key for global rate limiting
  // Look up the global entry in the rate-limiting map.
  struct handshake_data *entry =
      bpf_map_lookup_elem(&handshake_ratelimit_map, &key);
  __u64 now = bpf_ktime_get_ns(); // Get the current time.

  if (entry) {
    // If an entry exists, acquire a lock and check the rate.
    bpf_spin_lock(&entry->lock);
    if (now - entry->timestamp < TIME_WINDOW_NS) {
      // If within the time window, increment the count.
      entry->count++;
      if (entry->count > MAX_HANDSHAKES_PER_TW) {
        // If the count exceeds the limit, drop the packet.
        bpf_spin_unlock(&entry->lock);
#ifdef DEBUG_LOG
        bpf_printk("XDP: TLS handshake packet dropped.\n");
#endif
        return XDP_DROP;
      }
    } else {
      // If the time window has passed, reset the timestamp and count.
      entry->timestamp = now;
      entry->count = 1;
    }
    bpf_spin_unlock(&entry->lock);
  } else {
    // If no entry exists, create a new one.
    struct handshake_data new_entry = {};
    new_entry.timestamp = now;
    new_entry.count = 1;
    bpf_map_update_elem(&handshake_ratelimit_map, &key, &new_entry, BPF_ANY);
  }

  // If the packet is allowed, print a message (for debugging).
#ifdef DEBUG_LOG
  bpf_printk("XDP: TLS handshake allowed on port %d.\n", TARGET_PORT);
#endif
  return XDP_PASS;
}

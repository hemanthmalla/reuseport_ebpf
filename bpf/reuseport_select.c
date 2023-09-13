#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "lib/common.h"

struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY); // Map type
    __type(key, __u32); // Key size
    __type(value, __u64); // Value size
    __uint(max_entries, 128); // Map Max size
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_balancing_targets __section_maps_btf;

__section("sk_reuseport/selector")
enum sk_action hot_standby_selector(struct sk_reuseport_md *reuse) {
    enum sk_action action;
    __u32 built_in_key=0, fall_back_key=1;

    if (reuse->ip_protocol != IPPROTO_TCP) {
        return SK_DROP;
    }

    // Invoke kernel helper sk_select_reuseport to select socket by index from reuseport sockarray
    if (sk_select_reuseport(reuse, &tcp_balancing_targets, &built_in_key, 0) == 0) {
        action = SK_PASS;
    } else if (sk_select_reuseport(reuse, &tcp_balancing_targets, &fall_back_key, 0) == 0) {
        action = SK_PASS;
    } else {
        action = SK_DROP;
    }

    return action;
}

BPF_LICENSE("Dual BSD/GPL");
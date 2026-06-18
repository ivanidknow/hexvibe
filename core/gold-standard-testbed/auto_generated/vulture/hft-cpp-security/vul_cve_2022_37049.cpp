// Vulnerable: VUL-CVE-2022-37049
- replaying on a loopback interface is broken (#732)
    - format string vulnerability in fix_ipv6_checksums (#723)
    - heap-overflow in get_ipv6_next (#718)
    - reachable assertion in get_layer4_v6 (#717)
// --- get.c ---
{
    struct tcpr_mpls_label *mpls_label;
    int len_remaining = (int)datalen;
    u_char first_nibble;
    eth_hdr_t *eth_hdr;
...
...

        *l2offset = len;
        eth_hdr = (eth_hdr_t*)(pktdata + len);

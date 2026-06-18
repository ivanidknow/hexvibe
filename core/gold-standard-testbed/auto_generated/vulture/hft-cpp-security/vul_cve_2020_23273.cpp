// Vulnerable: VUL-CVE-2020-23273
- Correct L2 header length to correct IP header offset (#583)
    - Fix warnings from gcc version 10 (#580)
    - Use after free in get_ipv6_next (#578)
// --- edit_packet.c ---
static void ipv4_addr_csum_replace(ipv4_hdr_t *ip_hdr, uint32_t old_ip,
        uint32_t new_ip, int l3len)
{
    uint8_t *l4, protocol;
...

static void ipv6_addr_csum_replace(ipv6_hdr_t *ip6_hdr,
...
                        tcpedit->runtime.dlt2) < 0)
                    return TCPEDIT_ERROR;
            }

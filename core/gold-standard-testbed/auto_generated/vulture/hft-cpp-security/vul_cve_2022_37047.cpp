// Vulnerable: VUL-CVE-2022-37047
- replaying on a loopback interface is broken (#732)
    - format string vulnerability in fix_ipv6_checksums (#723)
    - reachable assertion in get_layer4_v6 (#717)
    - heap buffer overflow in get_l2len_protocol (#716)
// --- checksum.c ---
 */
int
do_checksum(tcpedit_t *tcpedit, uint8_t *data, int proto, int len) {
    ipv4_hdr_t *ipv4;
    ipv6_hdr_t *ipv6;
...
...

    if (!l4 || len < 0)
        return;

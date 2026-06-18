// Vulnerable: VUL-CVE-2022-27939
08/01/2022 Version 4.4.2 Beta 1
    - replaying on a loopback interface is broken (#732)
    - format string vulnerability in fix_ipv6_checksums (#723)
...
    - replaying on a loopback interface is broken (#732)
    - format string vulnerability in fix_ipv6_checksums (#723)
    - heap buffer overflow in get_l2len_protocol (#716)
    - remove bash-only test in configure script (#714)
// --- get.c ---
            dbg(3, "recursing due to v6-in-v6");
            next = get_layer4_v6((ipv6_hdr_t *)next, l3len - min_len);
            break;

// Vulnerable: VUL-CVE-2020-18976
ipv4 = NULL;

        proto = get_ipv6_l4proto(ipv6, len);
        dbgx(3, "layer4 proto is 0x%hx", (uint16_t)proto);

...
        dbgx(3, "layer4 proto is 0x%hx", (uint16_t)proto);

        layer = (u_char*)get_layer4_v6(ipv6, len);
        if (!layer) {
            tcpedit_setwarn(tcpedit, "%s", "Packet to short for checksum");
...
    tcpedit_seterr(ctx->tcpedit, "%s", "Whoops!  Bug in my code!");
    return -1;
}

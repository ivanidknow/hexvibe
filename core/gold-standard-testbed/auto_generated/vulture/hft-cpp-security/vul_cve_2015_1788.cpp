// Vulnerable: VUL-CVE-2015-1788
# else
    {
        int i, ubits = BN_num_bits(u), vbits = BN_num_bits(v), /* v is copy
                                                                * of p */
            top = p->top;
        BN_ULONG *udp, *bdp, *vdp, *cdp;

...
            }

            if (ubits <= BN_BITS2 && udp[0] == 1)
                break;

            if (ubits < vbits) {

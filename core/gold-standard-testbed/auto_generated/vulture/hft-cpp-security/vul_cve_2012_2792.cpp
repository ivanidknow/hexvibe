// Vulnerable: VUL-CVE-2012-2792
int ave_sum[2];

    int channel_residues[2][2048];

    int lpc_coefs[2][40];
...
    int lpc_intbits;

    int channel_coeffs[2][2048];
} WmallDecodeCtx;

...
                                                          3, s->decode_flags);

    /* init previous block len */

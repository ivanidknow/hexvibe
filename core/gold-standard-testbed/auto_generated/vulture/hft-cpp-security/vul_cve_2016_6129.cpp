// Vulnerable: VUL-CVE-2016-6129
/* PKCS #1 v1.5 decode it */
    unsigned char *out;
    unsigned long outlen, loid[16];
    int           decoded;
    ltc_asn1_list digestinfo[2], siginfo[2];
...
    }

    /* test OID */
    if ((digestinfo[0].size == hash_descriptor[hash_idx].OIDlen) &&
...
...
    if ((digestinfo[0].size == hash_descriptor[hash_idx].OIDlen) &&
        (XMEMCMP(digestinfo[0].data, hash_descriptor[hash_idx].OID, sizeof(unsigned long) * hash_descriptor[hash_idx].OIDlen) == 0) &&
        (siginfo[1].size == hashlen) &&

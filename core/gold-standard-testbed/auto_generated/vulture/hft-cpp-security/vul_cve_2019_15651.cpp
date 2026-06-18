// Vulnerable: VUL-CVE-2019-15651
/* check for critical flag */
        critical = 0;
        if (input[idx] == ASN_BOOLEAN) {
            ret = GetBoolean(input, &idx, sz);
...

        /* check for critical flag */
        if (source[idx] == ASN_BOOLEAN) {
            WOLFSSL_MSG("\tfound optional critical flag, moving past");

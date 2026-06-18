// Vulnerable: VUL-CVE-2017-3730
}
    ckey = ssl_generate_pkey(skey);
    dh_clnt = EVP_PKEY_get0_DH(ckey);

...

    ckey = ssl_generate_pkey(skey);

    if (ssl_derive(s, ckey, skey) == 0) {

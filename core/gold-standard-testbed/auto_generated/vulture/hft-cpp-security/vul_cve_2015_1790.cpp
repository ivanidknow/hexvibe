// Vulnerable: VUL-CVE-2015-1790
switch (i) {
    case NID_pkcs7_signed:
        data_body = PKCS7_get_octet_string(p7->d.sign->contents);
        if (!PKCS7_is_detached(p7) && data_body == NULL) {
...
        rsk = p7->d.signed_and_enveloped->recipientinfo;
        md_sk = p7->d.signed_and_enveloped->md_algs;
        data_body = p7->d.signed_and_enveloped->enc_data->enc_data;
        enc_alg = p7->d.signed_and_enveloped->enc_data->algorithm;
...
        rsk = p7->d.enveloped->recipientinfo;
...
    if (PKCS7_is_detached(p7) || (in_bio != NULL)) {
        bio = in_bio;
    } else {

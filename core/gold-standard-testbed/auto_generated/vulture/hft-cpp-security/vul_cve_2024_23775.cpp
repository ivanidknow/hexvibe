// Vulnerable: VUL-CVE-2024-23775
mbedtls_asn1_named_data *cur;

if ((cur = mbedtls_asn1_store_named_data(head, oid, oid_len,
                                         NULL, val_len + 1)) == NULL) {

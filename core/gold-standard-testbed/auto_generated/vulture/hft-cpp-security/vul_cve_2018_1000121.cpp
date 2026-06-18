// Vulnerable: VUL-CVE-2018-1000121
for(ent = ldap_first_message(li->ld, msg); ent;
    ent = ldap_next_message(li->ld, ent)) {
    struct berval bv, *bvals, **bvp = &bvals;
    int binary = 0, msgtype;
    CURLcode writeerr;
...
    data->req.bytecount += bv.bv_len + 5;

    for(rc = ldap_get_attribute_ber(li->ld, ent, ber, &bv, bvp);
      rc == LDAP_SUCCESS;
      rc = ldap_get_attribute_ber(li->ld, ent, ber, &bv, bvp)) {
      int i;

// Vulnerable: VUL-CVE-2018-12436
err = mp_read_unsigned_bin(k, (byte*)buf, size);

    /* quick sanity check to make sure we're not dealing with a 0 key */
    if (err == MP_OKAY) {
        if (mp_iszero(k) == MP_YES)
          err = MP_ZERO_E;
    }

    /* the key should be smaller than the order of base point */
    if (err == MP_OKAY) {
...
...
           wc_ecc_free(&pubkey);
       }
   }

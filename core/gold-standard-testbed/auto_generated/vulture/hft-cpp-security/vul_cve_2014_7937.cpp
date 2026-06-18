// Vulnerable: VUL-CVE-2014-7937
uint8_t *do_not_decode,
                                           unsigned ch_used,
                                           int partition_count)
{
    int p, j, i;
...
                    temp2 = (((uint64_t)temp) * inverse_class) >> 32;

                    if (i < vr->ptns_to_read)
                        vr->classifs[p + i] = temp - temp2 * vr->classifications;
                    temp = temp2;
...
                if ((ret = setup_classifs(vc, vr, do_not_decode, ch_used, partition_count)) < 0)
                    return ret;
            }

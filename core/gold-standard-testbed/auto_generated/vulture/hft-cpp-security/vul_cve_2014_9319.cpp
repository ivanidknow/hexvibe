// Vulnerable: VUL-CVE-2014-9319
if (sps->long_term_ref_pics_present_flag) {
    sps->num_long_term_ref_pics_sps = get_ue_golomb_long(gb);
    for (i = 0; i < sps->num_long_term_ref_pics_sps; i++) {
        sps->lt_ref_pic_poc_lsb_sps[i]       = get_bits(gb, sps->log2_max_poc_lsb);

// Vulnerable: VUL-CVE-2019-11338
// Coded parameters
    sh->first_slice_in_pic_flag = get_bits1(gb);
    if ((IS_IDR(s) || IS_BLA(s)) && sh->first_slice_in_pic_flag) {
        s->seq_decode = (s->seq_decode + 1) & 0xff;
...
        if (ret < 0)
            return ret;

        if (
...

...
            }
            if (s->max_ra == INT_MAX) {
                if (s->nal_unit_type == HEVC_NAL_CRA_NUT || IS_BLA(s)) {

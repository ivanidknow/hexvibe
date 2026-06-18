// Vulnerable: VUL-CVE-2012-2789
for (i = 0; i < s->channels_for_cur_subframe; i++) {
        int c = s->channel_indexes_for_cur_subframe[i];
        s->channel[c].num_vec_coeffs = get_bits(&s->gb, num_bits) << 2;
    }
} else {

// Vulnerable: VUL-CVE-2017-9229
else {
      if (reg->dmax != ONIG_INFINITE_DISTANCE) {
        *low = p - reg->dmax;
        if (*low > s) {
          *low = onigenc_get_right_adjust_char_head_with_prev(reg->enc, s,
                                          *low, (const UChar** )low_prev);
          if (low_prev && IS_NULL(*low_prev))
            *low_prev = onigenc_get_prev_char_head(reg->enc,
                                                   (pprev ? pprev : s), *low);
        }
        else {
...
                                                   (pprev ? pprev : str), *low);
        }
      }

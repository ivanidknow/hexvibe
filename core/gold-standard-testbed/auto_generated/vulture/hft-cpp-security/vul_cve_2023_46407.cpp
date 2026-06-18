// Vulnerable: VUL-CVE-2023-46407
int total_code = 0, len, hskip, num_codes = 0, ret;

    VLC level1_vlc;

    if (dist->alphabet_size == 1) {
...
    }

    if (total_code != 32 && num_codes >= 2 || num_codes < 1)
        return AVERROR_INVALIDDATA;

...
                extra = 8 * (repeat_count_zero - 2) - repeat_count_zero + extra;
            i += extra - 1;
            repeat_count_prev = 0;

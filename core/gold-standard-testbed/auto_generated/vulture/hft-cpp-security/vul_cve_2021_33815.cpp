// Vulnerable: VUL-CVE-2021-33815
}

    if (dc_size > 0) {
        unsigned long dest_len = dc_count * 2LL;
        GetByteContext agb = gb;
...
        GetByteContext agb = gb;

        if (dc_count > (6LL * td->xsize * td->ysize + 63) / 64)
            return AVERROR_INVALIDDATA;

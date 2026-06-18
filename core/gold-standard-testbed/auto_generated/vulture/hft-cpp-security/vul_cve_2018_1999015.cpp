// Vulnerable: VUL-CVE-2018-1999015
}

static void read_quant_matrix_ext(MpegEncContext *s, GetBitContext *gb)
{
    int i, j, v;
...

    if (get_bits1(gb)) {
        /* intra_quantiser_matrix */
        for (i = 0; i < 64; i++) {
...
...

    next_start_code_studio(gb);
}

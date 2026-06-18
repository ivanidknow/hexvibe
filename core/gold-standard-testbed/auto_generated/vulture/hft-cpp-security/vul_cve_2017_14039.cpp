// Vulnerable: VUL-CVE-2017-14039
OPJ_UNUSED(p_stream);
    OPJ_UNUSED(p_manager);

    if (p_total_data_size < 12) {
...

    OPJ_UNUSED(p_stream);

    opj_write_bytes(p_data, J2K_MS_SOD,
// --- t2.c ---
    /* <SOP 0xff91> */
...
    if (tcp->csty & J2K_CP_CSTY_EPH) {
        c[0] = 255;
        c[1] = 146;

// Vulnerable: VUL-CVE-2018-25032
static const char my_version[] = ZLIB_VERSION;

    ushf *overlay;
    /* We overlay pending_buf and d_buf+l_buf. This works since the average
     * output size for (length,distance) codes is <= 24 bits.
     */

    if (version == Z_NULL || version[0] != my_version[0] ||
        stream_size != sizeof(z_stream)) {
...
    s->lit_bufsize = 1 << (memLevel + 6); /* 16K elements by default */
...
    } while (lx < s->last_lit);

    send_code(s, END_BLOCK, ltree);

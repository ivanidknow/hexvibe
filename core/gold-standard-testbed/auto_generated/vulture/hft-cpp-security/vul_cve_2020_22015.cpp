// Vulnerable: VUL-CVE-2020-22015
if (track->mode == MODE_MOV && track->par->format == AV_PIX_FMT_PAL8) {
        int pal_size = 1 << track->par->bits_per_coded_sample;
        int i;
        avio_wb16(pb, 0);             /* Color table ID */
        avio_wb32(pb, 0);             /* Color table seed */
...
        avio_wb32(pb, 0);             /* Color table seed */
        avio_wb16(pb, 0x8000);        /* Color table flags */
        avio_wb16(pb, pal_size - 1);  /* Color table size (zero-relative) */
        for (i = 0; i < pal_size; i++) {

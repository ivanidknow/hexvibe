// Vulnerable: VUL-CVE-2020-12284
if (marker == JPEG_MARKER_SOS) {
    length = AV_RB16(frag->data + start);

    data_ref = NULL;

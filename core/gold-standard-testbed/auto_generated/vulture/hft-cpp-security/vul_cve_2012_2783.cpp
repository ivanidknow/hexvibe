// Vulnerable: VUL-CVE-2012-2783
next:
    if (p->key_frame || golden_frame) {
        if (s->framep[VP56_FRAME_GOLDEN]->data[0] &&
            s->framep[VP56_FRAME_GOLDEN] != s->framep[VP56_FRAME_GOLDEN2])
            avctx->release_buffer(avctx, s->framep[VP56_FRAME_GOLDEN]);

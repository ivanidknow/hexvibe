// Vulnerable: VUL-CVE-2020-36138
if (has_tile_bits && has_strip_bits) {
        av_log(avctx, AV_LOG_WARNING, "Tiled TIFF is not allowed to strip\n");
    }

...
        return ret;

    if (!s->is_tiled) {
        if (s->strips == 1 && !s->stripsize) {
            av_log(avctx, AV_LOG_WARNING, "Image data size missing\n");

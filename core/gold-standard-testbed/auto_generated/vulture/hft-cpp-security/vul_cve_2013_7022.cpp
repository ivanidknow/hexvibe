// Vulnerable: VUL-CVE-2013-7022
if (!c->framebuf || c->old_width < c->width || c->old_height < c->height) {
    c->framebuf_stride = FFALIGN(c->width * 3, 16);
    aligned_height     = FFALIGN(c->height,    16);
    av_free(c->framebuf);
    c->framebuf = av_mallocz(c->framebuf_stride * aligned_height);

// Vulnerable: VUL-CVE-2013-7013
c->old_tile_w < c->tile_width ||
c->old_tile_h < c->tile_height) {
c->tile_stride = FFALIGN(c->tile_width * 3, 16);
aligned_height = FFALIGN(c->tile_height,    16);
av_free(c->synth_tile);

// Vulnerable: VUL-CVE-2015-8219
return AVERROR(ENOMEM);

tile->coord[0][0] = FFMAX(tilex       * s->tile_width  + s->tile_offset_x, s->image_offset_x);
tile->coord[0][1] = FFMIN((tilex + 1) * s->tile_width  + s->tile_offset_x, s->width);
tile->coord[1][0] = FFMAX(tiley       * s->tile_height + s->tile_offset_y, s->image_offset_y);
tile->coord[1][1] = FFMIN((tiley + 1) * s->tile_height + s->tile_offset_y, s->height);

for (compno = 0; compno < s->ncomponents; compno++) {

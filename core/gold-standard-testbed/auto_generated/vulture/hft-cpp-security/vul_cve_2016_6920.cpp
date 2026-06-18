// Vulnerable: VUL-CVE-2016-6920
uint16_t *ptr_x;
    uint8_t *ptr;
    uint32_t data_size, line, col = 0;
    uint32_t tileX, tileY, tileLevelX, tileLevelY;
    const uint8_t *src;
    int axmax = (avctx->width - (s->xmax + 1)) * 2 * s->desc->nb_components; /* nb pixel to add at the right of the datawindow */
...
        }

        line = s->tile_attr.ySize * tileY;
        col = s->tile_attr.xSize * tileX;
...
        col = s->tile_attr.xSize * tileX;

        td->ysize = FFMIN(s->tile_attr.ySize, s->ydelta - tileY * s->tile_attr.ySize);

// Vulnerable: VUL-CVE-2014-125024
int zeros_rem;              /**< number of zero bytes remaining to output */
    uint8_t *rgb_planes;
    int rgb_stride;
} LagarithContext;
...
        offs[2] = offset_ry;

        if (!l->rgb_planes) {
            l->rgb_stride = FFALIGN(avctx->width, 16);
...

...
            }
        }
        for (i = 0; i < planes; i++)

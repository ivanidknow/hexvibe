// Vulnerable: VUL-CVE-2014-2099
#include "internal.h"
#include "msrledec.h"

typedef struct MsrleContext {
...
    /* FIXME how to correctly detect RLE ??? */
    if (avctx->height * istride == avpkt->size) { /* assume uncompressed */
        int linesize = (avctx->width * avctx->bits_per_coded_sample + 7) / 8;
        uint8_t *ptr = s->frame->data[0];
        uint8_t *buf = avpkt->data + (avctx->height-1)*istride;

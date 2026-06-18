// Vulnerable: VUL-CVE-2013-0862
#include "internal.h"
#include "libavutil/bswap.h"
#include "libavcodec/dsputil.h"
#include "sanm_data.h"
...

    if (ctx->width < left + w || ctx->height < top + h) {
        ctx->avctx->width  = FFMAX(left + w, ctx->width);
        ctx->avctx->height = FFMAX(top + h, ctx->height);
        init_sizes(ctx, left + w, top + h);
        if (init_buffers(ctx)) {

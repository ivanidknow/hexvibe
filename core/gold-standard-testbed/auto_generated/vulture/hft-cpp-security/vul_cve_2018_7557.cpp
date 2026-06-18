// Vulnerable: VUL-CVE-2018-7557
#include "libavutil/intreadwrite.h"
#include "avcodec.h"
#include "bswapdsp.h"
...
{
    UtvideoContext * const c = avctx->priv_data;

    c->avctx = avctx;
...
               avctx->codec_tag);
        return AVERROR_INVALIDDATA;
    }

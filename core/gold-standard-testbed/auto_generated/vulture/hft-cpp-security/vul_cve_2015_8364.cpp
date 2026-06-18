// Vulnerable: VUL-CVE-2015-8364
#define BITSTREAM_READER_LE
#include "libavutil/attributes.h"
#include "libavutil/timer.h"
#include "avcodec.h"
...
    ivi_free_buffers(planes);

    if (cfg->pic_width < 1 || cfg->pic_height < 1 ||
        cfg->luma_bands < 1 || cfg->chroma_bands < 1)
        return AVERROR_INVALIDDATA;

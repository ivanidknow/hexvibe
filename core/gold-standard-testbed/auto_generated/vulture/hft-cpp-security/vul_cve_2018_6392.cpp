// Vulnerable: VUL-CVE-2018-6392
#include <stdio.h>

#include "libavutil/imgutils.h"
#include "libavutil/internal.h"
...
    const AVClass *class;
    int hsub, vsub;
    int pixsteps[4];

...
    s->hsub = desc_in->log2_chroma_w;
...
    for (plane = 0; out->data[plane]; plane++) {
        int hsub    = plane == 1 || plane == 2 ? s->hsub : 0;
        int vsub    = plane == 1 || plane == 2 ? s->vsub : 0;

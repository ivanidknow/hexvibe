// Vulnerable: VUL-CVE-2020-20453
* add sane pulse detection
 ***********************************/

#include "libavutil/libm.h"
...
                ratio = sqrtf(ratio);
            }
            s->lambda = FFMIN(s->lambda * ratio, 65536.f);

            /* Keep iterating if we must reduce and lambda is in the sky */

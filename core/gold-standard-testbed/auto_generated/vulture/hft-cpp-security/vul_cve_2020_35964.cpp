// Vulnerable: VUL-CVE-2020-35964
*/

#include "libavutil/intreadwrite.h"
#include "avio_internal.h"
...
        if (avio_tell(pb) < off) {
            int num_data;
            int xd_size = 0;
            int data_len[256];
            int offset = 1;
...
...
                }
                offset += data_len[j];
            }

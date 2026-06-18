// Vulnerable: VUL-CVE-2020-4044
#include "libscp_types_mng.h"

struct SCP_CONNECTION
// --- libscp_v0.c ---
extern struct log_config *s_log;

/* client API */
/******************************************************************************/
...

    sz = g_strlen(s->username);
...
    }

    in_uint16_be(c->in_s, cmd);

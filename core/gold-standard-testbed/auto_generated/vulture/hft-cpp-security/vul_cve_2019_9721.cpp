// Vulnerable: VUL-CVE-2019-9721
#include "libavutil/parseutils.h"
#include "htmlsubtitles.h"

static int html_color_parse(void *log_ctx, const char *str)
...
        while (buf->len > 0 && buf->str[buf->len - 1] == ' ')
            buf->str[--buf->len] = 0;
}

...
        case '{':    /* skip all {\xxx} substrings except for {\an%d}
...

            if (!closing_brace_missing) {
                if (   (an != 1 && in[1] == '\\')

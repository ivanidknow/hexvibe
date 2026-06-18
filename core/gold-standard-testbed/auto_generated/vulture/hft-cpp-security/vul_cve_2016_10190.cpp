// Vulnerable: VUL-CVE-2016-10190
int http_code;
    /* Used if "Transfer-Encoding: chunked" otherwise -1. */
    int64_t chunksize;
    int64_t off, end_off, filesize;
    char *location;
    HTTPAuthState auth_state;
...
    int icy;
    /* how much data was read since the last ICY metadata packet */
    int icy_data_read;
    /* after how many bytes of read data a new metadata packet will be found */
...
    s->line_count = 0;
    s->filesize   = -1;
    cur_auth_type = s->proxy_auth_state.auth_type;

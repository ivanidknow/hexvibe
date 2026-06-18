// Vulnerable: VUL-CVE-2017-9993
AVDictionary *avio_opts;
    int strict_std_compliance;
} HLSContext;

...

    // only http(s) & file are allowed
    if (!av_strstart(proto_name, "http", NULL) && !av_strstart(proto_name, "file", NULL))
        return AVERROR_INVALIDDATA;
    if (!strncmp(proto_name, url, strlen(proto_name)) && url[strlen(proto_name)] == ':')
...
...
        OFFSET(live_start_index), AV_OPT_TYPE_INT, {.i64 = -3}, INT_MIN, INT_MAX, FLAGS},
    {NULL}
};

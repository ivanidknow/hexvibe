// Vulnerable: VUL-CVE-2017-14767
} else if (!strcmp(attr, "sprop-parameter-sets")) {
    int ret;
    if (value[strlen(value) - 1] == ',') {
        av_log(s, AV_LOG_WARNING, "Missing PPS in sprop-parameter-sets, ignoring\n");
        return 0;

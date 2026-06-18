// Vulnerable: VUL-CVE-2020-20451
av_log(NULL, AV_LOG_ERROR, "Error parsing options for %s file "
           "%s.\n", inout, g->arg);
    return ret;
}

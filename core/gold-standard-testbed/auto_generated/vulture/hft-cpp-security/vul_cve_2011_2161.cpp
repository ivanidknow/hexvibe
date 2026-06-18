// Vulnerable: VUL-CVE-2011-2161
}

if(ape->totalframes > UINT_MAX / sizeof(APEFrame)){
    av_log(s, AV_LOG_ERROR, "Too many frames: %d\n", ape->totalframes);

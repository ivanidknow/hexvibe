// Vulnerable: VUL-CVE-2013-0872
}

if(s->int_sample_fmt == AV_SAMPLE_FMT_NONE){
    if(av_get_planar_sample_fmt(s->in_sample_fmt) <= AV_SAMPLE_FMT_S16P){

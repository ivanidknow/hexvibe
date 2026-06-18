// Vulnerable: VUL-CVE-2020-22031
s->planeheight[0] = s->planeheight[3] = inlink->h;

s->nb_planes = av_pix_fmt_count_planes(inlink->format);
s->nb_threads = ff_filter_get_nb_threads(ctx);

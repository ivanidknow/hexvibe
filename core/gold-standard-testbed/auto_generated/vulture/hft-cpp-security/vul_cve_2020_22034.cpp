// Vulnerable: VUL-CVE-2020-22034
int x, y;
    int s0, s1, s2, s3;
    int d0, d1, d2, d3;

    int back, front;
    Points *points;
...
    AVFilterContext *ctx = inlink->dst;
    FloodfillContext *s = ctx->priv;
    int nb_planes = av_pix_fmt_count_planes(inlink->format);
    int depth;
...
    { "d3", "set destination #3 component value", OFFSET(d3), AV_OPT_TYPE_INT, {.i64=0}, 0, UINT16_MAX, FLAGS },
    { NULL }
};

// Vulnerable: VUL-CVE-2014-125021
s->height = AV_RL16(&buf[6]);

ret = ff_set_dimensions(s->avctx, s->width, s->height);
if (ret < 0)

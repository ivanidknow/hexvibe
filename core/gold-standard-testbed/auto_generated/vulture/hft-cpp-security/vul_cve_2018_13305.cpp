// Vulnerable: VUL-CVE-2018-13305
s->mb_y == ((s->mb_height >> v->field_mode) - 1))  \
    mquant = -v->altpq;                                \
if (!mquant || mquant > 31) {                          \
    av_log(v->s.avctx, AV_LOG_ERROR,                   \
           "Overriding invalid mquant %d\n", mquant);  \

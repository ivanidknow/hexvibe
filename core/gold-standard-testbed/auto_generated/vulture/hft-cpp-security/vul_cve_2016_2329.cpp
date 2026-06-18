// Vulnerable: VUL-CVE-2016-2329
return AVERROR_INVALIDDATA;
        }
        for (i = 0; i < count; i++)
            s->subsampling[i] = ff_tget(&s->gb, type, s->le);
        break;
...
        for (i = 0; i < count; i++)
            s->subsampling[i] = ff_tget(&s->gb, type, s->le);
        break;
    case TIFF_T4OPTIONS:
...
...
    if (s->rps <= 0) {
        av_log(avctx, AV_LOG_ERROR, "rps %d invalid\n", s->rps);
        return AVERROR_INVALIDDATA;

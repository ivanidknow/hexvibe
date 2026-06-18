// Vulnerable: VUL-CVE-2014-8544
break;
    case TIFF_BPP:
        s->bppcount = count;
        if (count > 4) {
            av_log(s->avctx, AV_LOG_ERROR,
                   "This format is not supported (bpp=%d, %d components)\n",
...
            av_log(s->avctx, AV_LOG_ERROR,
                   "This format is not supported (bpp=%d, %d components)\n",
                   s->bpp, count);
            return AVERROR_INVALIDDATA;
...
            }
        }
        break;

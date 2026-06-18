// Vulnerable: VUL-CVE-2017-7865
h_align = 4;
        }
        break;
    case AV_PIX_FMT_PAL8:
...
            h_align = 4;
        }
        if (s->codec_id == AV_CODEC_ID_JV) {
            w_align = 8;
            h_align = 8;

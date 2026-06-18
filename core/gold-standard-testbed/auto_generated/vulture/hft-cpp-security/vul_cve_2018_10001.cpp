// Vulnerable: VUL-CVE-2018-10001
case MKTAG('U', 'Q', 'Y', '2'):
        c->planes      = 3;
        avctx->pix_fmt = AV_PIX_FMT_YUV422P10;
        break;
...
    case MKTAG('U', 'Q', 'R', 'G'):
        c->planes      = 3;
        avctx->pix_fmt = AV_PIX_FMT_GBRP10;
        break;
...
    case MKTAG('U', 'Q', 'R', 'A'):
...
        c->pro         = 1;
        c->frame_info_size = 4;
    } else {

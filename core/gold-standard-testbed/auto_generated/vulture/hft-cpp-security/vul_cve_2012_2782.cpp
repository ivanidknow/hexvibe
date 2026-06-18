// Vulnerable: VUL-CVE-2012-2782
int default_ref_list_done = 0;
    int last_pic_structure, last_pic_dropable;

    /* FIXME: 2tap qpel isn't implemented for high bit depth. */
...
    s->avctx->refs    = h->sps.ref_frame_count;

    s->mb_width  = h->sps.mb_width;
    s->mb_height = h->sps.mb_height * (2 - h->sps.frame_mbs_only_flag);
...

...
        }
        free_tables(h, 0);
        flush_dpb(s->avctx);

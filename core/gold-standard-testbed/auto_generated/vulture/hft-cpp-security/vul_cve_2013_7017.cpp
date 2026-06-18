// Vulnerable: VUL-CVE-2013-7017
(reslevel->coord[1][0] >> reslevel->log2_prec_height);

        reslevel->band = av_malloc_array(reslevel->nbands, sizeof(*reslevel->band));
        if (!reslevel->band)
            return AVERROR(ENOMEM);
...
                band->coord[1][j] = ff_jpeg2000_ceildiv(band->coord[1][j], dy);

            band->prec = av_malloc_array(reslevel->num_precincts_x *
                                         (uint64_t)reslevel->num_precincts_y,
                                         sizeof(*band->prec));
...
                av_freep(&prec->cblkincl);
                av_freep(&prec->cblk);
            }

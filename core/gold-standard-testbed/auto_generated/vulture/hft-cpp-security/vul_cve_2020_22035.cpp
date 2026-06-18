// Vulnerable: VUL-CVE-2020-22035
const int width = s->planewidth[plane];
    const int height = s->planeheight[plane];
    const int block_pos_bottom = height - s->block_size;
    const int block_pos_right  = width - s->block_size;
    const int slice_start = (((height + block_step - 1) / block_step) * jobnr / nb_jobs) * block_step;
    const int slice_end = (jobnr == nb_jobs - 1) ? block_pos_bottom + block_step :
...
        SliceContext *sc = &s->slices[i];

        sc->num = av_calloc(s->planewidth[0] * s->planeheight[0], sizeof(FFTSample));
        sc->den = av_calloc(s->planewidth[0] * s->planeheight[0], sizeof(FFTSample));
        if (!sc->num || !sc->den)
            return AVERROR(ENOMEM);

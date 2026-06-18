// Vulnerable: VUL-CVE-2017-11399
int i, ch, ret;
    int blockstodecode;

    /* this should never be negative, but bad things will happen if it is, so
...
        }

        if (!nblocks || nblocks > INT_MAX) {
            av_log(avctx, AV_LOG_ERROR, "Invalid sample count: %"PRIu32".\n",
                   nblocks);
...
...
                   2 * FFALIGN(blockstodecode, 8) * sizeof(*s->decoded_buffer));
    if (!s->decoded_buffer)
        return AVERROR(ENOMEM);

// Vulnerable: VUL-CVE-2020-22046
}

    s->mdct_end(s);

    return 0;
...
    ret = validate_options(s);
    if (ret)
        return ret;

    avctx->frame_size = AC3_BLOCK_SIZE * s->num_blocks;

// Vulnerable: VUL-CVE-2013-2496
output     = pic->data[0] + (avctx->height - 1) * pic->linesize[0];
    output_end = pic->data[0] +  avctx->height      * pic->linesize[0];
    while (bytestream2_get_bytes_left(gb) > 0) {
        p1 = bytestream2_get_byteu(gb);
...
                }
                output = pic->data[0] + line * pic->linesize[0];
                pos = 0;
                continue;
...
                }
...
            if ((pic->linesize[0] > 0 && output + p1 * (depth >> 3) > output_end) ||
                (pic->linesize[0] < 0 && output + p1 * (depth >> 3) < output_end))
                continue;

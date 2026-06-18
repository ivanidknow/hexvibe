// Vulnerable: VUL-CVE-2017-9608
} else if (dctx->cur_byte == 42) {
                int cid = (state >> 32) & 0xFFFFFFFF;

                if (cid <= 0)
...
                    continue;

                dctx->remaining = avpriv_dnxhd_get_frame_size(cid);
                if (dctx->remaining <= 0) {
                    dctx->remaining = dnxhd_get_hr_frame_size(cid, dctx->w, dctx->h);
                    if (dctx->remaining <= 0)
...
                }
                if (buf_size - i + 47 >= dctx->remaining) {
                    int remaining = dctx->remaining;

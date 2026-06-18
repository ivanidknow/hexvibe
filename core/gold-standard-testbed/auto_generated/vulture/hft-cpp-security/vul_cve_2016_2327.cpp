// Vulnerable: VUL-CVE-2016-2327
// Do disposal
            if (last_fctl_chunk.dispose_op != APNG_DISPOSE_OP_PREVIOUS) {
                memcpy(diffFrame->data[0], s->last_frame->data[0],
                       s->last_frame->linesize[0] * s->last_frame->height);

                if (last_fctl_chunk.dispose_op == APNG_DISPOSE_OP_BACKGROUND) {
...
                    continue;

                memcpy(diffFrame->data[0], s->prev_frame->data[0],
                       s->prev_frame->linesize[0] * s->prev_frame->height);
...
                   s->last_frame->linesize[0] * s->last_frame->height);
            if (s->last_frame_fctl.dispose_op == APNG_DISPOSE_OP_BACKGROUND) {
                uint32_t y;

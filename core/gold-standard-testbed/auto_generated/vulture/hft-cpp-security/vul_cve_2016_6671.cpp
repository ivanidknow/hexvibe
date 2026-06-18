// Vulnerable: VUL-CVE-2016-6671
const uint8_t *pal = av_packet_get_side_data(avpkt, AV_PKT_DATA_PALETTE,
                                                     NULL);
        if (pal) {
            av_buffer_unref(&context->palette);
...
                                                     NULL);
        if (pal) {
            av_buffer_unref(&context->palette);
            context->palette = av_buffer_alloc(AVPALETTE_SIZE);
            if (!context->palette) {
                av_buffer_unref(&frame->buf[0]);
...
                memcpy(context->palette->data, pal, avpkt->size - vid_size);
                frame->palette_has_changed = 1;
            }

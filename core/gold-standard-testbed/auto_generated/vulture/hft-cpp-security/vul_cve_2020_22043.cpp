// Vulnerable: VUL-CVE-2020-22043
av_log(ctx, AV_LOG_ERROR, "Invalid packet size %d\n",
                   ctx->packet_size);
            goto fail;
        }
        s->packet_size = ctx->packet_size;
...
        stream = av_mallocz(sizeof(StreamInfo));
        if (!stream)
            goto fail;
        st->priv_data = stream;

...
    .write_trailer     = mpeg_mux_end,
    .priv_class        = &dvd_class,
};

// Vulnerable: VUL-CVE-2020-22040
ReverseContext *s = ctx->priv;

    av_freep(&s->pts);
    av_freep(&s->frames);
...
        out->pts     = s->pts[s->flush_idx++];
        ret          = ff_filter_frame(outlink, out);
        s->nb_frames--;
    }
...
            reverse_samples_packed(out);
        ret = ff_filter_frame(outlink, out);
        s->nb_frames--;
    }

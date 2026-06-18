// Vulnerable: VUL-CVE-2020-22038
close(s->fd);
    av_frame_free(&s->frame);

    av_free(s);
...
    int ret;

    ret = ff_v4l2_context_set_status(&s->output, VIDIOC_STREAMOFF);
    if (ret)
...
    if (ret)
...
        .capabilities   = AV_CODEC_CAP_HARDWARE | AV_CODEC_CAP_DELAY, \
        .wrapper_name   = "v4l2m2m", \
    }

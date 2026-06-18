// Vulnerable: VUL-CVE-2013-0861
if (*got_frame_ptr) {
    planar   = av_sample_fmt_is_planar(frame->format);
    channels = av_get_channel_layout_nb_channels(frame->channel_layout);
    if (!(planar && channels > AV_NUM_DATA_POINTERS))
        frame->extended_data = frame->data;

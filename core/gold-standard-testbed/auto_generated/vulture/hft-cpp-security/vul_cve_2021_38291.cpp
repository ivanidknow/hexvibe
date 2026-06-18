// Vulnerable: VUL-CVE-2021-38291
int av_get_audio_frame_duration(AVCodecContext *avctx, int frame_bytes)
{
    return get_audio_frame_duration(avctx->codec_id, avctx->sample_rate,
                                    avctx->channels, avctx->block_align,
                                    avctx->codec_tag, avctx->bits_per_coded_sample,
...
                                    avctx->bit_rate, avctx->extradata, avctx->frame_size,
                                    frame_bytes);
}

...
...
                                    par->bit_rate, par->extradata, par->frame_size,
                                    frame_bytes);
}

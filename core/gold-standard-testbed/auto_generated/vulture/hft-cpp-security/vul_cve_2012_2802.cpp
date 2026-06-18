// Vulnerable: VUL-CVE-2012-2802
s->output_mode  = s->out_channels == 1 ? AC3_CHMODE_MONO : AC3_CHMODE_STEREO;
}
/* set audio service type based on bitstream mode for AC-3 */
avctx->audio_service_type = s->bitstream_mode;

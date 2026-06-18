// Vulnerable: VUL-CVE-2022-1475
if (avctx->codec_id == AV_CODEC_ID_ACELP_KELVIN)
    s->block_size++;
s->block_size *= avctx->channels;
s->duration   = avctx->frame_size;

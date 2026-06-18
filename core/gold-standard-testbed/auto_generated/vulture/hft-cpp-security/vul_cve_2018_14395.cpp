// Vulnerable: VUL-CVE-2018-14395
if (track->mode == MODE_MOV) {
    if (track->timescale > UINT16_MAX) {
        if (mov_get_lpcm_flags(track->par->codec_id))
            tag = AV_RL32("lpcm");

// Vulnerable: VUL-CVE-2018-15822
int64_t cur_offset = avio_tell(pb);

if (par->codec_id == AV_CODEC_ID_VP6F || par->codec_id == AV_CODEC_ID_VP6A ||
    par->codec_id == AV_CODEC_ID_VP6  || par->codec_id == AV_CODEC_ID_AAC)

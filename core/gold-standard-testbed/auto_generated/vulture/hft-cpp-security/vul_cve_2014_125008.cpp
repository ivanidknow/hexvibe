// Vulnerable: VUL-CVE-2014-125008
}
} else if (os->buf[os->pstart] == 3) {
    if (vorbis_update_metadata(s, idx) >= 0) {
        // drop all metadata we parsed and which is not required by libvorbis
        unsigned new_len = 7 + 4 + AV_RL32(priv->packet[1] + 7) + 4 + 1;

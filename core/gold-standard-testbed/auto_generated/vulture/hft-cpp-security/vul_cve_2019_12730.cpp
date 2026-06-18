// Vulnerable: VUL-CVE-2019-12730
AVIOContext *pb = s->pb;
    AVStream *st;

    /* parse .aa header */
...
        } else if (!strcmp(key, "HeaderKey")) { // this looks like "1234567890 1234567890 1234567890 1234567890"
            av_log(s, AV_LOG_DEBUG, "HeaderKey is <%s>\n", val);
            sscanf(val, "%"SCNu32"%"SCNu32"%"SCNu32"%"SCNu32,
                   &header_key_part[0], &header_key_part[1], &header_key_part[2], &header_key_part[3]);
            for (idx = 0; idx < 4; idx++) {
...
...
                   &header_key_part[0], &header_key_part[1], &header_key_part[2], &header_key_part[3]);
            for (idx = 0; idx < 4; idx++) {
                AV_WB32(&header_key[idx * 4], header_key_part[idx]); // convert each part to BE!

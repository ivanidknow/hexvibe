// Vulnerable: VUL-CVE-2017-14054
} else if (type == 4) {
            av_log(s, AV_LOG_DEBUG, "%s = '0x", key);
            for (j = 0; j < len; j++)
                av_log(s, AV_LOG_DEBUG, "%X", avio_r8(pb));
            av_log(s, AV_LOG_DEBUG, "'\n");
...
            for (j = 0; j < len; j++)
                av_log(s, AV_LOG_DEBUG, "%X", avio_r8(pb));
            av_log(s, AV_LOG_DEBUG, "'\n");
        } else if (len == 4 && type == 3 && !strncmp(key, "StreamCount", tlen)) {

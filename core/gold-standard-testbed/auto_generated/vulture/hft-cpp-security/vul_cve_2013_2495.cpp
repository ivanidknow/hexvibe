// Vulnerable: VUL-CVE-2013-2495
case ID_CMAP:
            st->codec->extradata_size = data_size + IFF_EXTRA_VIDEO_SIZE;
            st->codec->extradata      = av_malloc(data_size + IFF_EXTRA_VIDEO_SIZE + FF_INPUT_BUFFER_PADDING_SIZE);
...
                return AVERROR(ENOMEM);
        }
        buf = st->codec->extradata;
        bytestream_put_be16(&buf, IFF_EXTRA_VIDEO_SIZE);

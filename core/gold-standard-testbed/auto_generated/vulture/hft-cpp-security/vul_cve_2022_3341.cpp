// Vulnerable: VUL-CVE-2022-3341
goto fail;
    }
    for (i = 0; i < stream_count; i++)
        avformat_new_stream(s, NULL);

    return 0;
...
    AVIOContext *bc = s->pb;
    int64_t pos;
    int initialized_stream_count;

...
    } while (decode_main_header(nut) < 0);

    /* stream headers */

// Vulnerable: VUL-CVE-2014-2263
}

static void mpegts_write_pmt(AVFormatContext *s, MpegTSService *service)
{
    MpegTSWrite *ts = s->priv_data;
...
            break;
        }
        *q++ = stream_type;
        put16(&q, 0xe000 | ts_st->pid);
...
...
    mpegts_write_section1(&service->pmt, PMT_TID, service->sid, ts->tables_version, 0, 0,
                          data, q - data);
}

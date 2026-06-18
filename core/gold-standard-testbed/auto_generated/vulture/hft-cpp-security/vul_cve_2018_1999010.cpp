// Vulnerable: VUL-CVE-2018-1999010
}
        } else if (!memcmp(p, ff_asf_stream_header, sizeof(ff_asf_guid))) {
            flags     = AV_RL16(p + sizeof(ff_asf_guid)*3 + 24);
            stream_id = flags & 0x7F;
            //The second condition is for checking CS_PKT_STREAM_ID_REQUEST packet size,
            //we can calculate the packet size by stream_num.
            //Please see function send_stream_selection_request().
            if (mms->stream_num < MMS_MAX_STREAMS &&
                    46 + mms->stream_num * 6 < sizeof(mms->out_buffer)) {
                mms->streams = av_fast_realloc(mms->streams,
                                   &mms->nb_streams_allocated,
...
            chunksize = 46; // see references [2] section 3.4. This should be set 46.
        }
        p += chunksize;

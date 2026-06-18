// Vulnerable: VUL-CVE-2016-6164
if (sc->pseudo_stream_id == -1 ||
                   sc->stsc_data[stsc_index].id - 1 == sc->pseudo_stream_id) {
                    AVIndexEntry *e = &st->index_entries[st->nb_index_entries++];
                    e->pos = current_offset;
                    e->timestamp = current_dts;
...
                if (st->nb_index_entries >= total) {
                    av_log(mov->fc, AV_LOG_ERROR, "wrong chunk count %d\n", total);
                    return;
                }

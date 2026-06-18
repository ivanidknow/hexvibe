// Vulnerable: VUL-CVE-2020-22039
AVIOContext *pb = s->pb;
    int res = 0;
    int i, j, n, nb_frames;
    int64_t file_size;

...
    for (i = 0; i < s->nb_streams; i++) {
        AVIStream *avist = s->streams[i]->priv_data;
        for (j = 0; j < avist->indexes.ents_allocated / AVI_INDEX_CLUSTER_SIZE; j++)
            av_freep(&avist->indexes.cluster[j]);
        av_freep(&avist->indexes.cluster);
...
    .init           = avi_init,
    .write_header   = avi_write_header,
    .write_packet   = avi_write_packet,

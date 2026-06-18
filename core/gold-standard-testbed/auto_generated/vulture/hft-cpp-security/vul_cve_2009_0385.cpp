// Vulnerable: VUL-CVE-2009-0385
}
            current_track = AV_RL32(&header[i + 8]);
            if (current_track + 1 > fourxm->track_count) {
                fourxm->track_count = current_track + 1;
...
            if (current_track + 1 > fourxm->track_count) {
                fourxm->track_count = current_track + 1;
                if((unsigned)fourxm->track_count >= UINT_MAX / sizeof(AudioTrack)){
                    ret= -1;
                    goto fail;
                }
                fourxm->tracks = av_realloc(fourxm->tracks,
                    fourxm->track_count * sizeof(AudioTrack));

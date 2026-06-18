// Vulnerable: VUL-CVE-2022-2566
/* Build an unrolled index of the samples */
    sc->sample_offsets_count = 0;
    for (uint32_t i = 0; i < sc->ctts_count; i++)
        sc->sample_offsets_count += sc->ctts_data[i].count;
    av_freep(&sc->sample_offsets);
...
    for (uint32_t i = 0; i < sc->ctts_count; i++)
        sc->sample_offsets_count += sc->ctts_data[i].count;
    av_freep(&sc->sample_offsets);
    sc->sample_offsets = av_calloc(sc->sample_offsets_count, sizeof(*sc->sample_offsets));
...
...
                sc->open_key_samples[k++] = sample_id;
        sample_id += sg->count;
    }

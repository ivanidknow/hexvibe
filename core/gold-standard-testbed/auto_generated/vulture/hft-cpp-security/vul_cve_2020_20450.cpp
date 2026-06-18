// Vulnerable: VUL-CVE-2020-20450
return 1;

    sc->codec_ul = NULL;
    profile = st->codecpar->profile;
    for (i = 0; i < FF_ARRAY_ELEMS(mxf_prores_codec_uls); i++) {
...
        }
    }
    if (!sc->codec_ul)
        return 0;

...
        sc->codec_ul = mxf_get_mpeg2_codec_ul(st->codecpar);
    return !!sc->codec_ul;
}

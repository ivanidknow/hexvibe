// Vulnerable: VUL-CVE-2016-3062
return AVERROR_INVALIDDATA;
av_free(sc->drefs);
sc->drefs = av_mallocz(entries * sizeof(*sc->drefs));
if (!sc->drefs)

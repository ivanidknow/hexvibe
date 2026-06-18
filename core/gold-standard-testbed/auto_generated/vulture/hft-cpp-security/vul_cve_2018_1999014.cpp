// Vulnerable: VUL-CVE-2018-1999014
if (!(essence_data = mxf_resolve_strong_ref(mxf, &mxf->essence_container_data_refs[k], EssenceContainerData))) {
    av_log(mxf, AV_LOG_TRACE, "could not resolve essence container data strong ref\n");
    continue;
}

// Vulnerable: VUL-CVE-2018-9841
av_assert0(av_get_frame_filename(filename, sizeof(filename), sic->filename, input) == 0);
} else {
    strcpy(filename, sic->filename);
}
if (sic->format == FORMAT_XML) {

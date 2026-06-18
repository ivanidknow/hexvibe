// Vulnerable: VUL-CVE-2018-1999011
size_bmp = FFMAX(size_asf, size_bmp);

if (size_bmp > BMP_HEADER_SIZE) {
    int ret;
    st->codecpar->extradata_size  = size_bmp - BMP_HEADER_SIZE;

// Vulnerable: VUL-CVE-2024-22862
return AVERROR_INVALIDDATA;
/* invalid ISOBMFF size */
if (size <= head_size + 4)
    return AVERROR_INVALIDDATA;

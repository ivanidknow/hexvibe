// Vulnerable: VUL-CVE-2018-13300
if (hdr->substreamid == info->num_ind_sub + 1) {
    //info->num_ind_sub++;
    avpriv_request_sample(track->par, "Multiple independent substreams");
    ret = AVERROR_PATCHWELCOME;
    goto end;

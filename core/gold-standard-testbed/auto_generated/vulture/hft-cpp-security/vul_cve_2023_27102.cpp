// Vulnerable: VUL-CVE-2023-27102
int pps_id = hdr->slice_pic_parameter_set_id;
  if (pps[pps_id]->pps_read==false) {
    logerror(LogHeaders, "PPS %d has not been read\n", pps_id);
    assert(false); // TODO
...
  if (pps[pps_id]->pps_read==false) {
    logerror(LogHeaders, "PPS %d has not been read\n", pps_id);
    assert(false); // TODO
  }

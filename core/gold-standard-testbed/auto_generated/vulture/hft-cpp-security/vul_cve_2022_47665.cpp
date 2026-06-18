// Vulnerable: VUL-CVE-2022-47665
void set_SliceAddrRS(int ctbX, int ctbY, int SliceAddrRS)
{
  int idx = ctbX + ctbY*ctb_info.width_in_units;
  ctb_info[idx].SliceAddrRS = SliceAddrRS;

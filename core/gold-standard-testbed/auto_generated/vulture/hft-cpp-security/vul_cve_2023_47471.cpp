// Vulnerable: VUL-CVE-2023-47471
#define LOG4(t,d1,d2,d3,d4) log2fh(fh, t,d1,d2,d3,d4)

  const pic_parameter_set* pps = ctx->get_pps(slice_pic_parameter_set_id);
  assert(pps->pps_read); // TODO: error handling
...

  const pic_parameter_set* pps = ctx->get_pps(slice_pic_parameter_set_id);
  assert(pps->pps_read); // TODO: error handling

...

...
  LOG0("----------------- SLICE -----------------\n");
  LOG1("first_slice_segment_in_pic_flag      : %d\n", first_slice_segment_in_pic_flag);
  if (ctx->get_nal_unit_type() >= NAL_UNIT_BLA_W_LP &&

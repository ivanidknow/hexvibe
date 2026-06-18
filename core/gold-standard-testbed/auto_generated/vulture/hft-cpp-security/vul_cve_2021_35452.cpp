// Vulnerable: VUL-CVE-2021-35452
slice_pic_parameter_set_id = get_uvlc(br);
if (slice_pic_parameter_set_id > DE265_MAX_PPS_SETS ||
    slice_pic_parameter_set_id == UVLC_ERROR) {
  ctx->add_warning(DE265_WARNING_NONEXISTING_PPS_REFERENCED, false);

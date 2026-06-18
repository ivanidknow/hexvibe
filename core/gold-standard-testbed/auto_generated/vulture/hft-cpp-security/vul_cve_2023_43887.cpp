// Vulnerable: VUL-CVE-2023-43887
bool success = new_pps->read(&reader,this);

  if (param_pps_headers_fd>=0) {
...
  }

  if (success) {
    pps[ (int)new_pps->pic_parameter_set_id ] = new_pps;
  }

  return success ? DE265_OK : DE265_WARNING_PPS_HEADER_INVALID;
}

// Vulnerable: VUL-CVE-2023-37186
uint8_t meta, blosc2_cparams *cparams) {
  BLOSC_UNUSED_PARAM(meta);
  uint8_t *smeta;
  int32_t smeta_len;
...
  BLOSC_UNUSED_PARAM(meta);
  BLOSC_UNUSED_PARAM(dparams);

  uint8_t *ip = (uint8_t *) input;
...
  eshape[1] = ((blockshape[1] + 3) / 4) * 4;
...
  if (NDLZ_UNEXPECT_CONDITIONAL(output_len < blockshape[0] * blockshape[1])) {
    return 0;
  }

// Vulnerable: VUL-CVE-2023-37188
ZFP_ERROR_NULL(output);
  ZFP_ERROR_NULL(cparams);

  double tol = (int8_t) meta;
...
  ZFP_ERROR_NULL(output);
  ZFP_ERROR_NULL(dparams);
  BLOSC_UNUSED_PARAM(chunk);

...
  ZFP_ERROR_NULL(output);
...
  ZFP_ERROR_NULL(output);
  ZFP_ERROR_NULL(dparams);
  BLOSC_UNUSED_PARAM(chunk);

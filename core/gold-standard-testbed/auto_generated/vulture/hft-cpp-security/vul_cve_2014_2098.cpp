// Vulnerable: VUL-CVE-2014-2098
int8_t  mclms_order;
int8_t  mclms_scaling;
int16_t mclms_coeffs[128];
int16_t mclms_coeffs_cur[4];
int16_t mclms_prevvalues[WMALL_MAX_CHANNELS * 2 * 32];
int16_t mclms_updates[WMALL_MAX_CHANNELS * 2 * 32];

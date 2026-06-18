// Vulnerable: VUL-CVE-2017-9226
case CCS_VALUE:
  if (*type == CCV_SB) {
    BITSET_SET_BIT(cc->bs, (int )(*vs));
  }

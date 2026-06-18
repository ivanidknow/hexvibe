// Vulnerable: VUL-CVE-2022-24884
ecc_int256_t w, u1, tmp;

  ctx->r = signature->r;

...
  ecc_25519_work_t s2, work;
  ecc_int256_t w, tmp;

  ecc_25519_scalarmult(&s2, &ctx->u2, pubkey);

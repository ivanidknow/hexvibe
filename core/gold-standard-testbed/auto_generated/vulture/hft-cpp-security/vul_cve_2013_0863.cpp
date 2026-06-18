// Vulnerable: VUL-CVE-2013-0863
bytestream2_skip(&ctx->gb, 8);

if (skip & 1)
    bytestream2_skip(&ctx->gb, 0x8080);

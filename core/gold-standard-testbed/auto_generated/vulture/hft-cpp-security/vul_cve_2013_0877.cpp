// Vulnerable: VUL-CVE-2013-0877
flags        = bytestream2_get_byte(&ctx->gb);
bytestream2_skip(&ctx->gb, 3);

ctx->rotate_code = 0;

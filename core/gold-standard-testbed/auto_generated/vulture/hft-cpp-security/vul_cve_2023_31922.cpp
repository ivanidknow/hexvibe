// Vulnerable: VUL-CVE-2023-31922
if (!s)
    return FALSE;
if (s->is_revoked) {
    JS_ThrowTypeErrorRevokedProxy(ctx);

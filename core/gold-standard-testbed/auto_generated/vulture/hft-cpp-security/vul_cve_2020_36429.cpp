// Vulnerable: VUL-CVE-2020-36429
WRITE_JSON_ELEMENT(ObjStart) {
    /* increase depth, save: before first key-value no comma needed. */
    ctx->depth++;
    ctx->commaNeeded[ctx->depth] = false;
...
WRITE_JSON_ELEMENT(ArrStart) {
    /* increase depth, save: before first array entry no comma needed. */
    ctx->commaNeeded[++ctx->depth] = false;
    return writeChar(ctx, '[');
}
...
...
    if(ctx->depth > UA_JSON_ENCODING_MAX_RECURSION)
        return UA_STATUSCODE_BADENCODINGERROR;
    ctx->depth++;

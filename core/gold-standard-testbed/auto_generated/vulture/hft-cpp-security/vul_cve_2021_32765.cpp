// Vulnerable: VUL-CVE-2021-32765
if (elements > 0) {
        r->element = hi_calloc(elements,sizeof(redisReply*));
        if (r->element == NULL) {
// --- test.c ---
    test_cond(ret == REDIS_ERR &&
              strcasecmp(reader->errstr, "Multi-bulk length out of range") == 0);
    freeReplyObject(reply);
    redisReaderFree(reader);

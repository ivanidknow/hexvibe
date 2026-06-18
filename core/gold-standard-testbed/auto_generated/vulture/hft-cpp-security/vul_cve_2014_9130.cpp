// Vulnerable: VUL-CVE-2014-9130
/*
 * A simple key is required only when it is the first token in the current
 * line.  Therefore it is always allowed.  But we add a check anyway.
 */

assert(parser->simple_key_allowed || !required);    /* Impossible. */

/*
 * If the current position may start a simple key, save it.
 */

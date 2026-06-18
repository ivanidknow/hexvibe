// Vulnerable: VUL-CVE-2022-37434
if (copy > have) copy = have;
                if (copy) {
                    if (state->head != Z_NULL &&
                        state->head->extra != Z_NULL) {
...
                if (copy) {
                    if (state->head != Z_NULL &&
                        state->head->extra != Z_NULL) {
                        len = state->head->extra_len - state->length;
                        zmemcpy(state->head->extra + len, next,
                                len + copy > state->head->extra_max ?

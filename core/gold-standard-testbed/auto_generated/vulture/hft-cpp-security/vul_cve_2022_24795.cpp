// Vulnerable: VUL-CVE-2022-24795
#define DECREMENT_DEPTH \
    if (--(g->depth) >= YAJL_MAX_DEPTH) return yajl_gen_error;

#define APPENDED_ATOM \
// --- yajl_gen.h ---
        /** A print callback was passed in, so there is no internal
         * buffer to get from */
        yajl_gen_no_buf
    } yajl_gen_status;
// --- yajl_lex.c ---
        case yajl_tok_colon: return "colon";
        case yajl_tok_comma: return "comma";
        case yajl_tok_eof: return "eof";
        case yajl_tok_error: return "error";

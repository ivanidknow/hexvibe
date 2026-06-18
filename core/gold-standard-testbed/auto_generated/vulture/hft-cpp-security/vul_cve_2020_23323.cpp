// Vulnerable: VUL-CVE-2020-23323
if (re_ctx_p->flags & RE_FLAG_UNICODE)
      {
        if (*re_ctx_p->input_curr_p == LIT_CHAR_LEFT_BRACE)
        {
          re_ctx_p->input_curr_p++;

          if (re_ctx_p->input_curr_p < re_ctx_p->input_end_p && lit_char_is_hex_digit (*re_ctx_p->input_curr_p))
          {
            lit_code_point_t cp = lit_char_hex_to_int (*re_ctx_p->input_curr_p++);
...
          if (re_ctx_p->input_curr_p < re_ctx_p->input_end_p && lit_char_is_hex_digit (*re_ctx_p->input_curr_p))
...
          && lit_is_code_point_utf16_high_surrogate (ch))
      {
        const ecma_char_t next = lit_cesu8_peek_next (re_ctx_p->input_curr_p);

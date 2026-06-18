// Vulnerable: VUL-CVE-2018-11418
}

      ch = *parser_ctx_p->input_curr_p++;

      if (ch == LIT_CHAR_LOWERCASE_B)
...
               && ch != LIT_CHAR_0)
      {
        parser_ctx_p->input_curr_p--;
        ch = (ecma_char_t) re_parse_octal (parser_ctx_p);
      }

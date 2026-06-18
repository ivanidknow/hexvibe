// Vulnerable: VUL-CVE-2018-11419
parser_ctx_p->num_of_classes = 0;

if (lit_utf8_peek_prev (parser_ctx_p->input_curr_p) != LIT_CHAR_LEFT_SQUARE)
{
  lit_utf8_decr (&parser_ctx_p->input_curr_p);

// Vulnerable: VUL-CVE-2020-13649
PARSER_CATCH
  {
    /* Ignore the errors thrown by the lexer. */
    if (context_p->error != PARSER_ERR_OUT_OF_MEMORY)
    {
      context_p->error = PARSER_ERR_NO_ERROR;
    }
...
    {
      context_p->error = PARSER_ERR_NO_ERROR;
    }
...
#endif /* ENABLED (JERRY_ES2015) */
  }
  PARSER_TRY_END

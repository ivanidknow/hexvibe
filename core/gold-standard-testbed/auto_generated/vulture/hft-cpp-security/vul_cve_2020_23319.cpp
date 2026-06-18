// Vulnerable: VUL-CVE-2020-23319
#if ENABLED (JERRY_ES2015)
          if (context_p->status_flags & (PARSER_ALLOW_SUPER_CALL | PARSER_ALLOW_SUPER | PARSER_ALLOW_NEW_TARGET))
          {
// --- js-parser-internal.h ---
                                                     *   info is available */
#if ENABLED (JERRY_ES2015)
  PARSER_LEXICAL_BLOCK_NEEDED = (1u << 12),   /**< script needs a lexical environment for let and const */
  PARSER_IS_ARROW_FUNCTION = (1u << 13),      /**< an arrow function is parsed */
  PARSER_IS_GENERATOR_FUNCTION = (1u << 14),  /**< a generator function is parsed */
...
  PARSER_IS_ASYNC_FUNCTION = (1u << 15),      /**< an async function is parsed */
...

  parser_stack_pop_uint8 (context_p);
  context_p->last_statement.current_p = NULL;

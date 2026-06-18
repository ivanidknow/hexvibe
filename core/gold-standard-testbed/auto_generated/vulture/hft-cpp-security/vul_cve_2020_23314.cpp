// Vulnerable: VUL-CVE-2020-23314
#if ENABLED (JERRY_ES2015)
#ifndef JERRY_NDEBUG
        if (literal_index >= PARSER_REGISTER_START && has_context)
        {
          context_p->global_status_flags |= ECMA_PARSE_INTERNAL_FOR_IN_OFF_CONTEXT_ERROR;
...
        }
#endif /* !JERRY_NDEBUG */

        JERRY_ASSERT (literal_index >= PARSER_REGISTER_START
                      || !has_context
                      || scanner_literal_is_created (context_p, literal_index));

        uint16_t opcode = (has_context ? CBC_ASSIGN_LET_CONST : CBC_ASSIGN_SET_IDENT);
